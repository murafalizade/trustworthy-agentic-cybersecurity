from typing import Optional

from pydantic import BaseModel, field_validator


class CVERecord(BaseModel):
    """Authoritative intel for one CVE, merged from CISA KEV + EPSS ingestion.
    This is ground truth the CTI Agent cross-checks LLM output against —
    never populated from unstructured RSS/news text.
    """

    source: str  # the CVE identifier, e.g. "CVE-2024-12345"

    status: Optional[str] = None

    in_kev: bool = False
    epss_score: Optional[float] = None

    description: Optional[str] = None  # affected vendor/product + CISA's short description
    vulnerability: Optional[str] = None  # CISA KEV vulnerability name
    reason: Optional[str] = None  # why this record has its current status
    actions: Optional[str] = None  # recommended/required remediation action(s)

    last_updated: Optional[str] = None

    @field_validator("source")
    @classmethod
    def _normalize_source(cls, v: str) -> str:
        return v.upper()
