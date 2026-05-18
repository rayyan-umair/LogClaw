"""
LogClaw Brain - Sigma Rules API
sigma.py - Sigma rule management, import, and testing endpoints

Author  : Rayyan Umair
Date    : 2026-05-09
Purpose : REST endpoints for managing Sigma detection rules at
          runtime. List active rules, import new rules from YAML,
          disable rules, test rules against sample events, and
          view match statistics. No restart required - all changes
          take effect immediately.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/LogClaw

"Technology evolves quickly. Responsibility does not."
"""

# ── Standard Library ──────────────────────────────────────────────────────────
from typing import Any, Dict, List, Optional

# ── Third Party ───────────────────────────────────────────────────────────────
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

router = APIRouter()


# ── Request Models ────────────────────────────────────────────────────────────

class ImportRuleRequest(BaseModel):
    yaml_content: str


class TestRuleRequest(BaseModel):
    yaml_content: str
    test_events:  List[Dict[str, Any]]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/")
async def get_rules(
    request:     Request,
    active_only: bool = Query(default=True),
) -> Dict[str, Any]:
    """Get all loaded Sigma rules."""
    rules = await request.app.state.sigma_engine.get_all_rules()
    return {
        "rules": rules,
        "count": len(rules),
    }


@router.get("/stats")
async def get_sigma_stats(request: Request) -> Dict[str, Any]:
    """Get Sigma engine statistics and top matching rules."""
    return await request.app.state.sigma_engine.get_stats()


@router.get("/{rule_id}")
async def get_rule(
    request: Request,
    rule_id: str,
) -> Dict[str, Any]:
    """Get a single Sigma rule by ID."""
    rule = await request.app.state.sigma_engine.get_rule(rule_id)
    if not rule:
        raise HTTPException(
            status_code=404,
            detail=f"Rule {rule_id} not found",
        )
    return rule


@router.post("/import")
async def import_rule(
    request: Request,
    body:    ImportRuleRequest,
) -> Dict[str, Any]:
    """
    Import a new Sigma rule from YAML at runtime.
    The rule is validated and added to the active rule set immediately.
    No restart required.
    """
    success, message = await request.app.state.sigma_engine.import_rule(
        body.yaml_content
    )
    if not success:
        raise HTTPException(status_code=400, detail=message)

    return {
        "imported": True,
        "message":  message,
    }


@router.delete("/{rule_id}")
async def disable_rule(
    request: Request,
    rule_id: str,
) -> Dict[str, Any]:
    """
    Disable a Sigma rule by ID.
    The rule is removed from active evaluation immediately.
    """
    removed = await request.app.state.sigma_engine.disable_rule(rule_id)
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"Rule {rule_id} not found",
        )
    return {
        "rule_id":  rule_id,
        "disabled": True,
    }


@router.post("/test")
async def test_rule(
    request: Request,
    body:    TestRuleRequest,
) -> Dict[str, Any]:
    """
    Test a Sigma rule against a set of sample events.
    The rule is NOT added to the active rule set.
    Returns match results per event.
    """
    if not body.test_events:
        raise HTTPException(
            status_code=400,
            detail="Provide at least one test event in test_events",
        )

    result = await request.app.state.sigma_engine.test_rule(
        yaml_content=body.yaml_content,
        test_events=body.test_events,
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


@router.post("/reload")
async def reload_rules(request: Request) -> Dict[str, Any]:
    """
    Reload all Sigma rules from disk.
    Picks up any new .yml files added to the rules/ directory.
    """
    await request.app.state.sigma_engine.load_rules()
    stats = await request.app.state.sigma_engine.get_stats()
    return {
        "reloaded": True,
        "total_rules": stats["total_rules"],
    }