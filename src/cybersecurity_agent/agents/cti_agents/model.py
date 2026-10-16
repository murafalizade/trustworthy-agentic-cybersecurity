from typing import Optional, List
from pydantic import BaseModel, Field


class RelevantCVE(BaseModel):
    cve_id: str = Field(description="Exactly as given in the batch.")
    reasoning: str = Field(description="1-2 sentences explaining why this is relevant.")


class RelevantFindings(BaseModel):
    relevant: List[RelevantCVE] = Field(
        default_factory=list,
        description="Only CVEs judged relevant to our systems. Omit anything irrelevant or unconfirmed entirely.",
    )

