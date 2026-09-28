from typing import Literal, Optional
from pydantic import BaseModel, Field


class IDDecision(BaseModel):
    should_act: bool = Field(
        description="True if the alert clearly warrants an automated remediation action."
    )
    action: Literal["block_ip", "revoke_user", "bash_script", "sql_script", "none"] = Field(
        default="none", description="Which action tool to invoke, or 'none' if no action is warranted."
    )
    target: Optional[str] = Field(
        default=None, description="IP address (for block_ip), username (for revoke_user), sql code or bash script  to act on."
    )
    reasoning: str = Field(description="Short explanation for the decision.")
