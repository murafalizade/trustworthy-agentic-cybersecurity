from typing import Callable, Optional

from langchain_core.messages import HumanMessage, ToolMessage
from langchain_nvidia_ai_endpoints import ChatNVIDIA
from pydantic import ValidationError

from cybersecurity_agent.agents.id_agent.model import AnomalyVerdict
from cybersecurity_agent.agents.id_agent.prompt import ANOMALY_DETECTION_PROMPT
from cybersecurity_agent.agents.id_agent.tools import (
    # check_event_frequency,
    check_unusual_hour,
    classify_ip_address,
    # lookup_affected_asset,
    scan_for_attack_patterns,
)
from cybersecurity_agent.utils.settings import get_settings

settings = get_settings()

_MAX_TOOL_ITERATIONS = 4

# Reasoning models (e.g. gpt-oss) spend a large share of their completion
# budget on hidden reasoning_content before writing the actual answer. Too
# low a budget here means the real content gets truncated mid-JSON on the
# final structured-output call, and `with_structured_output` silently
# returns None instead of raising (see its docstring) - so this has to be
# generous enough to leave room for reasoning AND the final verdict.
_MAX_COMPLETION_TOKENS = 2048
_MAX_DECISION_RETRIES = 1

class IDAgent:
    """Intrusion Detection Agent: triages raw log entries for anomalous or
    malicious activity, grounding its verdict in deterministic tool evidence
    (signature matching, IP classification, event-frequency tracking, asset
    correlation) rather than judging log text from reasoning alone — the
    same tool-then-decide shape as CTIAgent's relevance triage.
    """

    def __init__(
        self,
        model_name: str = "meta/llama-3.1-8b-instruct",
        on_event: Optional[Callable[[dict], None]] = None,
    ):
        self.on_event = on_event
        self.model_name = model_name
        self.llm = ChatNVIDIA(
            model=model_name,
            api_key=settings.NVIDIA_API_KEY.get_secret_value(),
            temperature=0.1,
            max_completion_tokens=_MAX_COMPLETION_TOKENS,
        )

        self._tools = [
            scan_for_attack_patterns,
            classify_ip_address,
            # check_event_frequencxy,
            # lookup_affected_asset,
            check_unusual_hour,
        ]
        self._tools_by_name = {t.name: t for t in self._tools}
        self.tool_llm = self.llm.bind_tools(self._tools)
        self.decision_llm = self.llm.with_structured_output(AnomalyVerdict)

    def analyze_log(self, log_text: str) -> AnomalyVerdict:
        """Runs the triage conversation for one log entry/batch, letting the
        model call the detection tools as many or as few times as it judges
        necessary before finalizing an anomaly verdict.

        `log_text` is passed through to the prompt only inside a clearly
        delimited, explicitly-labeled "untrusted data" block (see prompt.py)
        — it is never concatenated into instruction text, so content crafted
        to look like a system/user instruction stays inert data for the LLM
        to analyze rather than a directive it could follow.
        """
        messages = ANOMALY_DETECTION_PROMPT.format_messages(
            log_text=log_text,
        )

        for _ in range(_MAX_TOOL_ITERATIONS):
            response = self.tool_llm.invoke(messages)
            if not response.tool_calls:
                if response.content:
                    messages.append(response)
                break

            messages.append(response)
            for call in response.tool_calls:
                tool = self._tools_by_name.get(call["name"])
                result = tool.invoke(call["args"]) if tool is not None else f"Unknown tool: {call['name']}"
                messages.append(ToolMessage(content=str(result), tool_call_id=call["id"]))
        messages.append(HumanMessage(
            content="Finalize now: based only on this system prompt's rules and the tool evidence "
                    "gathered above return your anomaly verdict."
        ))
        # `with_structured_output` returns None (rather than raising) when the
        # model's response doesn't parse into AnomalyVerdict - typically a
        # reasoning model running out of completion budget mid-answer. Retry
        # a couple of times before failing loudly: for an IDS, a swallowed
        # None is itself a false negative, so it must never look like "no
        # anomaly found".
        verdict = None
        for attempt in range(_MAX_DECISION_RETRIES):
            verdict = self.decision_llm.invoke(messages)
            if verdict is not None:
                break
            messages.append(HumanMessage(
                content="Failed to parse the structured output. Please return ONLY the requested JSON schema."
            ))

        if verdict is None:
            raise RuntimeError(
                "IDAgent could not produce a structured AnomalyVerdict via native structured "
                "output or the manual JSON fallback - treat this as 'unknown', not 'no anomaly'."
            )
        return verdict
