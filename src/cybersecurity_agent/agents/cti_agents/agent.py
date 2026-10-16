import asyncio
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait as wait_futures
from typing import Callable, Optional

from langchain_core.messages import HumanMessage, ToolMessage
from langchain_nvidia_ai_endpoints import ChatNVIDIA

from cybersecurity_agent.agents.cti_agents.model import RelevantFindings
from cybersecurity_agent.agents.cti_agents.utils.util import format_kev_entry
from cybersecurity_agent.database.model import CVERecord
from cybersecurity_agent.database.db import SqliteDb, utc_now_iso
from cybersecurity_agent.agents.cti_agents.prompt import RELEVANCE_PROMPT
from cybersecurity_agent.agents.cti_agents.tools import find_relative_component
from cybersecurity_agent.agents.cti_agents.utils.scrapers import fetch_epss_scores, fetch_kev_catalog
from cybersecurity_agent.utils.system_recon import build_system_snapshot
from cybersecurity_agent.utils.settings import get_settings

settings = get_settings()

_TRIAGED_STATUSES = {"relevant", "irrelevant", "defended"}

_BATCH_SIZE = 10
_MAX_RELEVANCE_TOOL_ITERATIONS = 4

_MAX_CONCURRENT_BATCHES = 4


class CTIAgent:
    def __init__(
        self,
        model_name: str = "meta/llama-3.1-8b-instruct",
        on_event: Optional[Callable[[dict], None]] = None,
        intel_store: Optional[SqliteDb] = None,
    ):
        self.on_event = on_event
        self.model_name = model_name
        self.intel_store = intel_store or SqliteDb()
        self.llm = ChatNVIDIA(
            model=model_name,
            api_key=settings.NVIDIA_API_KEY.get_secret_value(),
            temperature=0.3
        )

        self._relevance_tools = [find_relative_component]
        self._relevance_tools_by_name = {t.name: t for t in self._relevance_tools}
        self.relevance_tool_llm = self.llm.bind_tools(self._relevance_tools)
        self.relevance_decision_llm = self.llm.with_structured_output(RelevantFindings)


    def _investigate_relevance_batch(self, system_snapshot: str, batch_text: str) -> Optional[RelevantFindings]:
        """Runs the triage conversation for one batch, letting the model call
        `find_relative_component` as many or as few times as it judges
        necessary before finalizing which CVEs are relevant.
        """
        messages = RELEVANCE_PROMPT.format_messages(system_snapshot=system_snapshot, batch_text=batch_text)

        for _ in range(_MAX_RELEVANCE_TOOL_ITERATIONS):
            response = self.relevance_tool_llm.invoke(messages)
            messages.append(response)
            if not response.tool_calls:
                break
            for call in response.tool_calls:
                tool = self._relevance_tools_by_name.get(call["name"])
                result = tool.invoke(call["args"]) if tool is not None else f"Unknown tool: {call['name']}"
                messages.append(ToolMessage(content=str(result), tool_call_id=call["id"]))

        messages.append(HumanMessage(
            content="Finalize now: list only the CVEs you've determined ARE relevant to our systems, "
                    "each with your reasoning."
        ))
        return self.relevance_decision_llm.invoke(messages)

    def run_kev_triage_cycle(self, stop_event: Optional[asyncio.Event] = None) -> None:
        """Pull the CISA KEV catalog and triage every CVE not already triaged.

        Every untriaged entry is judged by the LLM — no deterministic
        pre-filter, since a keyword match can miss things a model would
        reasonably catch — but entries are batched (see _BATCH_SIZE) and
        batches run concurrently (see _MAX_CONCURRENT_BATCHES) against one
        real system snapshot, so a 1700+-entry catalog stays a bounded,
        parallelized number of LLM calls instead of one sequential call per
        entry.

        Only CVEs the model judges relevant are saved to the store (status=
        'relevant'). Anything it doesn't name is not written at all — so it
        has no 'irrelevant' row and will be re-triaged on the next cycle.

        `stop_event` (anything with `.is_set()` — an `asyncio.Event` or
        `threading.Event`) is polled throughout, not just between cycles, so
        a caller can interrupt a cycle already in progress. On interruption
        we don't wait for batches already in flight to finish (that's what
        made Stop/Ctrl+C appear to hang) — they keep running in the
        background, bounded by the LLM client's own request timeout, and are
        simply not awaited.
        """
        if stop_event is not None and stop_event.is_set():
            return

        kev_entries = fetch_kev_catalog()
        system_snapshot = build_system_snapshot()

        if stop_event is not None and stop_event.is_set():
            return

        to_triage = []
        skipped = 0
        for entry in kev_entries:
            cve_id = entry.get("cveID")
            if not cve_id:
                continue
            existing = self.intel_store.get(cve_id)
            if existing is not None and existing.status in _TRIAGED_STATUSES:
                skipped += 1
                continue
            to_triage.append((cve_id, entry, existing))

        if stop_event is not None and stop_event.is_set():
            return

        epss_scores = fetch_epss_scores([cve_id for cve_id, _, _ in to_triage])

        batches = []
        for batch_idx, i in enumerate(range(0, len(to_triage), _BATCH_SIZE), start=1):
            batch = to_triage[i:i + _BATCH_SIZE]
            batch_text = "\n".join(
                format_kev_entry(cve_id, entry, epss_scores.get(cve_id.upper()))
                for cve_id, entry, _ in batch
            )
            batch_by_id = {cve_id.upper(): (cve_id, entry, existing) for cve_id, entry, existing in batch}
            batches.append((batch_idx, batch_text, batch_by_id))

        saved = 0
        pool = ThreadPoolExecutor(max_workers=_MAX_CONCURRENT_BATCHES)
        try:
            future_to_batch = {
                pool.submit(self._investigate_relevance_batch, system_snapshot, batch_text): (batch_idx, batch_by_id)
                for batch_idx, batch_text, batch_by_id in batches
            }
            pending = set(future_to_batch)
            while pending:
                if stop_event is not None and stop_event.is_set():
                    print(f"[!] KEV triage cycle interrupted: {len(pending)} batch(es) still in flight "
                          f"(left to finish in the background), {saved} already saved.")
                    return
                done, pending = wait_futures(pending, timeout=1.0, return_when=FIRST_COMPLETED)
                for future in done:
                    batch_idx, batch_by_id = future_to_batch[future]
                    try:
                        findings = future.result()
                    except Exception as e:
                        print(f"[!] Batch {batch_idx} relevance investigation failed, skipping batch for retry next cycle: {e}")
                        continue

                    print(f"[*] Batch {batch_idx} findings: {findings}")
                    if findings is None:
                        continue

                    for finding in findings.relevant:
                        match = batch_by_id.get(finding.cve_id.upper())
                        if match is None:
                            continue  # model named a CVE outside this batch; ignore
                        cve_id, entry, existing = match

                        record = existing or CVERecord(source=cve_id)
                        record.in_kev = True

                        record.description = entry.get('shortDescription') or None
                        record.vulnerability = entry.get("vulnerabilityName")
                        record.actions = entry.get("requiredAction")

                        epss = epss_scores.get(cve_id.upper())
                        if epss:
                            record.epss_score = epss["epss"]

                        record.last_updated = utc_now_iso()
                        record.status = "relevant"
                        record.reason = finding.reasoning

                        self.intel_store.upsert(record)
                        saved += 1
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

        print(
            f"[*] KEV triage cycle complete: {len(kev_entries)} KEV entries scanned, "
            f"{saved} saved as relevant across {len(batches)} batch(es), "
            f"{skipped} already-triaged skipped."
        )

    async def run_intel_sync_periodic(
        self,
        interval_seconds: int = 3600,
        stop_event: Optional[asyncio.Event] = None,
    ) -> None:
        """Repeatedly fetches the CISA KEV catalog and triages relevance,
        persisting whatever each cycle finds to the shared intel store.
        Runs each cycle in a worker thread (`asyncio.to_thread`) rather than
        calling it inline — a direct call would block this coroutine (and
        the whole event loop) for the cycle's full duration, starving
        whatever is bridging an external stop signal in here and making Stop
        only take effect between cycles. Runs until `stop_event` is set.
        """
        stop_event = stop_event or asyncio.Event()
        print(f"[*] Starting periodic CTI intel sync (KEV) every {interval_seconds}s")
        while not stop_event.is_set():
            try:
                await asyncio.to_thread(self.run_kev_triage_cycle, stop_event)
            except Exception as e:
                print(f"[!] Intel sync cycle failed: {e}")
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval_seconds)
            except asyncio.TimeoutError:
                pass
        print("[*] Periodic CTI intel sync stopped.")
