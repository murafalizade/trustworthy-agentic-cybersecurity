from typing import Optional, List
from pydantic import BaseModel, Field


class ThreatAlert(BaseModel):
    is_cybersecurity_threat: bool = Field(
        description="Set to true if the item describes an active cyber threat, vulnerability, or IoC."
    )
    cve_or_id: Optional[str] = Field(
        default=None, description="CVE identifier or vulnerability tag if present."
    )
    severity: str = Field(
        default="UNKNOWN", description="Assessed severity: CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN."
    )
    extracted_iocs: List[str] = Field(
        default_factory=list, description="Extracted IP addresses, malicious domains, or file hashes."
    )
    summary: str = Field(
        description="A concise summary of the threat for the Intrusion Detection agent."
    )