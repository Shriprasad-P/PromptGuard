"""API request and response models."""

from typing import List, Optional
from pydantic import BaseModel, Field


class GuardCheckRequest(BaseModel):
    """Request to check text for injection."""
    
    text: str = Field(..., description="Text to check for injection patterns")
    channel: str = Field(default="prompt", description="Channel type: 'prompt' or 'tool_arg'")


class MatchedRuleResponse(BaseModel):
    """A matched detection rule."""
    
    rule_id: str
    description: str
    weight: int
    matched_text: str


class GuardCheckResponse(BaseModel):
    """Response from guard check."""
    
    decision: str = Field(..., description="Decision: 'allow', 'review', or 'block'")
    score: int = Field(..., description="Detection score (0-100)")
    matched_rules: List[MatchedRuleResponse]
    reasons: List[str]
    threshold: int = Field(..., description="Current block threshold")


class AgentRunRequest(BaseModel):
    """Request to run agent task."""
    
    task: str = Field(..., description="Coding task for the agent")


class AgentRunResponse(BaseModel):
    """Response from agent run."""
    
    status: str
    message: str
    guard_decision: str
    guard_score: int


class AuditEventResponse(BaseModel):
    """Audit event response."""
    
    id: int
    timestamp: str
    channel: str
    decision: str
    score: float
    threshold: int
    text_snippet: str
    matched_rules: Optional[str]
    reasons: Optional[str]


class ConfigThresholdResponse(BaseModel):
    """Configuration threshold response."""
    
    block_threshold: int


class ConfigThresholdUpdate(BaseModel):
    """Update block threshold."""
    
    block_threshold: int = Field(..., ge=0, le=100, description="New threshold (0-100)")
