from typing import Callable, Optional

from langchain_core.prompts import ChatPromptTemplate
from langchain_nvidia_ai_endpoints import ChatNVIDIA

from cybersecurity_agent.agents.cti_agents.model import ThreatAlert
from cybersecurity_agent.agents.id_agents.model import IDDecision
from cybersecurity_agent.agents.id_agents.tools import block_ip, revoke_user, run_sql, run_bash
from cybersecurity_agent.config import get_nvidia_api_key


class IDAgent:
    def __init__(self, model_name: str = "meta/llama-3.1-8b-instruct", on_event: Optional[Callable[[dict], None]] = None):
        """
        Initialize the Intrusion Detection (ID) Agent. Receives structured
        ThreatAlerts handed off from the CTI Agent and decides whether an
        automated remediation action is warranted before touching any tool.
        `on_event`, if provided, is called with a structured dict for each step
        (received/decision/action_result/error) for the Streamlit UI to render.
        """
        self.on_event = on_event
        self.llm = ChatNVIDIA(
            model=model_name,
            api_key=get_nvidia_api_key(),
            temperature=0.0
        )

        self.structured_llm = self.llm.with_structured_output(IDDecision)

        self.prompt = ChatPromptTemplate.from_messages([
            ("system", (
                "You are an Intrusion Detection (ID) Agent. A CTI Agent hands you structured threat "
                "alerts; you decide whether an automated remediation action is warranted.\n"
                "Available actions: 'block_ip' (target = a malicious IP address), "
                "'revoke_user' (target = a compromised username), or 'none'.\n"
                "'sql_script' (target = sql script) for protecting system running useful sql code\n"
                "'bash_script' (target = bash/sh script) for protecting system running sh/bash script\n"
                "Only set should_act=True when the alert has a concrete, actionable target and "
                "sufficient severity/confidence. Low-confidence, informational, or target-less alerts "
                "should result in should_act=False and action='none'."
            )),
            ("user", "CTI Alert:\n{alert_json}\n\nOriginal raw feed text:\n{raw_text}")
        ])

        self.chain = self.prompt | self.structured_llm

    def _emit(self, event_type: str, **payload):
        if self.on_event:
            self.on_event({"agent": "ID", "type": event_type, **payload})

    def receive_alert(self, alert: ThreatAlert, raw_text: str = "") -> IDDecision:
        """Receives a ThreatAlert handed off from the CTI Agent and decides whether to act."""
        print("\n[ID Agent] Received alert from CTI Agent.")
        self._emit("received", alert=alert.model_dump())
        try:
            decision: IDDecision = self.chain.invoke({
                "alert_json": alert.model_dump_json(indent=2),
                "raw_text": raw_text,
            })
        except Exception as e:
            print(f"[!] ID Agent failed to produce a structured decision: {e}")
            decision = IDDecision(
                should_act=False, action="none",
                reasoning=f"Decision generation failed, defaulting to no action: {e}"
            )
            self._emit("error", error=str(e))

        if decision is None:
            print("[!] ID Agent returned no structured decision (model likely refused or failed to conform to schema).")
            decision = IDDecision(
                should_act=False, action="none",
                reasoning="LLM returned None instead of a structured decision, defaulting to no action"
            )
            self._emit("error", error="LLM returned None instead of a structured IDDecision")

        print(decision)
        self._emit("decision", decision=decision.model_dump())

        if decision.should_act and decision.action != "none" and decision.target:
            self._execute(decision)
        else:
            print("[ID Agent Decision]: No action taken.")

        return decision

    def _execute(self, decision: IDDecision):
        print(f"\n[ID Agent]: Executing action '{decision.action}' -> {decision.target}")
        if decision.action == "block_ip":
            result = block_ip(decision.target)
        elif decision.action == "sql_script":
            result = run_sql(decision.target)
        elif decision.action == "bash_script":
            result = run_bash(decision.target)
        elif decision.action == "revoke_user":
            result = revoke_user(decision.target)
        else:
            result = None
        self._emit("action_result", action=decision.action, target=decision.target, result=result)
