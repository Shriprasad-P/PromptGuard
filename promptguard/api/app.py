"""FastAPI application and endpoints."""

from datetime import datetime
from typing import List
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import json

from promptguard.config import settings
from promptguard.core.database import init_db, get_session_maker, AuditEvent, ConfigHistory
from promptguard.core.rules import RuleEngine, get_decision
from promptguard.core.samples import ATTACK_SAMPLES, BENIGN_SAMPLES, TOOL_ARG_ATTACKS, TOOL_ARG_BENIGN
from promptguard.api.models import (
    GuardCheckRequest,
    GuardCheckResponse,
    MatchedRuleResponse,
    AgentRunRequest,
    AgentRunResponse,
    AuditEventResponse,
    ConfigThresholdResponse,
    ConfigThresholdUpdate,
)

app = FastAPI(
    title="PromptGuard",
    description="Prompt injection defense gateway for coding agents",
    version="0.1.0"
)

templates = Jinja2Templates(directory="promptguard/templates")

engine = init_db(settings.database_url)
SessionLocal = get_session_maker(engine)
rule_engine = RuleEngine()

current_threshold = settings.block_threshold


def get_db():
    """Database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_token(request: Request):
    """Verify admin bearer token."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header"
        )
    
    token = auth_header.split(" ")[1]
    if token != settings.guard_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    """Main dashboard with live check form."""
    recent_events = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(50).all()
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "threshold": current_threshold,
        "recent_events": recent_events,
        "attack_samples": ATTACK_SAMPLES[:10],
        "benign_samples": BENIGN_SAMPLES[:10],
    })


@app.post("/v1/guard/check", response_model=GuardCheckResponse)
async def check_guard(
    request: GuardCheckRequest,
    db: Session = Depends(get_db)
):
    """
    Check text for prompt injection patterns.
    
    Returns a decision (allow/review/block) with score and matched rules.
    """
    if request.channel not in ("prompt", "tool_arg"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Channel must be 'prompt' or 'tool_arg'"
        )
    
    score, matched_rules = rule_engine.check(request.text, request.channel)
    decision = get_decision(score, current_threshold)
    
    reasons = []
    if decision == "block":
        reasons.append(f"Score {score} exceeds threshold {current_threshold}")
    elif decision == "review":
        reasons.append(f"Score {score} in review range (40-{current_threshold-1})")
    
    for rule in matched_rules:
        reasons.append(f"{rule.description} (weight {rule.weight})")
    
    text_snippet = request.text[:200]
    matched_rules_json = json.dumps([
        {"id": r.rule_id, "desc": r.description, "weight": r.weight, "match": r.matched_text}
        for r in matched_rules
    ])
    
    audit = AuditEvent(
        channel=request.channel,
        decision=decision,
        score=score,
        threshold=current_threshold,
        text_snippet=text_snippet,
        matched_rules=matched_rules_json,
        reasons="; ".join(reasons)
    )
    db.add(audit)
    db.commit()
    
    return GuardCheckResponse(
        decision=decision,
        score=score,
        matched_rules=[
            MatchedRuleResponse(
                rule_id=r.rule_id,
                description=r.description,
                weight=r.weight,
                matched_text=r.matched_text
            )
            for r in matched_rules
        ],
        reasons=reasons,
        threshold=current_threshold
    )


@app.post("/v1/agent/run", response_model=AgentRunResponse)
async def run_agent(
    request: AgentRunRequest,
    db: Session = Depends(get_db)
):
    """
    Run a simulated coding agent task after guard check.
    
    Returns 403 if guard blocks the request.
    """
    score, matched_rules = rule_engine.check(request.task, "prompt")
    decision = get_decision(score, current_threshold)
    
    reasons = [f"{r.description} (weight {r.weight})" for r in matched_rules]
    text_snippet = request.task[:200]
    matched_rules_json = json.dumps([
        {"id": r.rule_id, "desc": r.description, "weight": r.weight, "match": r.matched_text}
        for r in matched_rules
    ])
    
    audit = AuditEvent(
        channel="agent_run",
        decision=decision,
        score=score,
        threshold=current_threshold,
        text_snippet=text_snippet,
        matched_rules=matched_rules_json,
        reasons="; ".join(reasons) if reasons else "No issues detected"
    )
    db.add(audit)
    db.commit()
    
    if decision == "block":
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "status": "blocked",
                "message": f"Request blocked by PromptGuard (score: {score})",
                "guard_decision": decision,
                "guard_score": score
            }
        )
    
    simulated_result = f"[SIMULATED] Processed task: {request.task[:50]}..."
    
    return AgentRunResponse(
        status="success" if decision == "allow" else "success_with_review",
        message=simulated_result,
        guard_decision=decision,
        guard_score=score
    )


@app.get("/audit", response_model=List[AuditEventResponse])
async def get_audit_log(
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    """
    Get audit log entries (append-only, no DELETE).
    
    Returns most recent entries first.
    """
    events = db.query(AuditEvent)\
        .order_by(AuditEvent.timestamp.desc())\
        .limit(limit)\
        .offset(offset)\
        .all()
    
    return [
        AuditEventResponse(
            id=event.id,
            timestamp=event.timestamp.isoformat(),
            channel=event.channel,
            decision=event.decision,
            score=event.score,
            threshold=event.threshold,
            text_snippet=event.text_snippet,
            matched_rules=event.matched_rules,
            reasons=event.reasons
        )
        for event in events
    ]


@app.get("/config/threshold", response_model=ConfigThresholdResponse)
async def get_threshold(token_check: None = Depends(verify_token)):
    """Get current block threshold (requires auth)."""
    return ConfigThresholdResponse(block_threshold=current_threshold)


@app.put("/config/threshold", response_model=ConfigThresholdResponse)
async def update_threshold(
    update: ConfigThresholdUpdate,
    token_check: None = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Update block threshold (requires auth)."""
    global current_threshold
    
    old_value = current_threshold
    current_threshold = update.block_threshold
    
    history = ConfigHistory(
        key="block_threshold",
        old_value=str(old_value),
        new_value=str(current_threshold),
        changed_by="admin"
    )
    db.add(history)
    db.commit()
    
    return ConfigThresholdResponse(block_threshold=current_threshold)


@app.get("/samples")
async def get_samples():
    """Get sample prompts for testing."""
    return {
        "attacks": {
            "prompts": ATTACK_SAMPLES,
            "tool_args": TOOL_ARG_ATTACKS
        },
        "benign": {
            "prompts": BENIGN_SAMPLES,
            "tool_args": TOOL_ARG_BENIGN
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "promptguard"}
