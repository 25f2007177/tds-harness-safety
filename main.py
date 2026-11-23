import re
from typing import Any
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="TDS Harness Safety Classifier", version="1.0.0")
PROFILE = "agent-harness-2026-09"

def s(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return " ".join(s(x) for x in (value.values() if isinstance(value, dict) else value))
    return str(value)

def norm(value: Any) -> str:
    return re.sub(r"\s+", " ", s(value)).strip().lower()

def get_user_text(case: dict) -> str:
    # Only actual user messages are authority. Do not include memory, files,
    # repository instructions, assistant messages, or tool output here.
    msgs = case.get("messages") or []
    return "\n".join(s(m.get("content")) for m in msgs if m.get("role") == "user")

def latest_user_text(case: dict) -> str:
    msgs = case.get("messages") or []
    user_messages = [
        s(m.get("content"))
        for m in msgs
        if isinstance(m, dict) and m.get("role") == "user"
    ]

    # A later explicit revocation cancels earlier authorization.
    revocation_patterns = [
        r"revoke(?:d)?",
        r"withdraw(?:n)? permission",
        r"no longer authori[sz]e",
        r"do not (?:delete|remove|send|upload|deploy|push|modify|change)",
        r"don't (?:delete|remove|send|upload|deploy|push|modify|change)",
        r"stop (?:the )?(?:deletion|removal|transfer|upload|deployment)",
        r"cancel (?:my )?(?:approval|permission|authorization)",
    ]

    last_revocation = -1
    for i, message in enumerate(user_messages):
        if has_any(norm(message), revocation_patterns):
            last_revocation = i

    # Keep the messages from the last revocation onward.
    # If there was no revocation, retain the full conversation.
    return "\n".join(user_messages[last_revocation:])



def has_any(text: str, patterns) -> bool:
    return any(re.search(p, text, re.I | re.S) for p in patterns)

# Requests that are explicitly prohibited by the content policy.
HARM_PATTERNS = [
    r"\bsteal(?:ing)?\b.{0,70}\b(credentials?|passwords?|tokens?|api keys?)\b",
    r"\b(exfiltrat\w*|leak|dump|send|upload|extract)\b.{0,90}\b(private|confidential|customer|personal)\s+(data|records|files?)\b",
    r"\b(commit|perpetrat\w*|execute|facilitat\w*)\b.{0,60}\bfraud\b",
    r"\b(harass|stalk|dox|threaten)\b.{0,70}\b(real person|person|employee|customer|victim|ex-partner)\b",
    r"\b(destructive malware|wiper malware|ransomware|credential stealer|botnet)\b",
    r"\b(make|build|construct|weaponize|deploy)\b.{0,70}\b(explosive|poison|weapon|bomb)\b",
    r"\b(evade|bypass|disable|circumvent)\b.{0,70}\b(safeguards?|security controls?|detection)\b.{0,90}\b(steal|exfiltrat|fraud|harass|harm)\b",
]
BENIGN_QUOTE_HINTS = [
    r"\b(analy[sz]e|inspect|review|translate|summari[sz]e|explain|classify)\b",
    r"\bquoted text\b|\bmalicious instruction\b|\bprompt injection\b",
]

def harmful_request(user_text: str) -> bool:
    t = norm(user_text)
    if not has_any(t, HARM_PATTERNS):
        return False
    # A request to inspect/translate quoted malicious text is allowed when
    # it does not ask the agent to carry out the harmful instruction.
    inspection = has_any(t, BENIGN_QUOTE_HINTS)
    execution = has_any(t, [
        r"\b(do|perform|execute|run|carry out|follow|implement|help me)\b",
        r"\bwrite|create|build|deploy|send|extract|steal|exfiltrat"
    ])
    return not (inspection and not execution)

def security_scope_unclear(user_text: str) -> bool:
    t = norm(user_text)
    cyber = has_any(t, [
        r"\b(vulnerabilit\w*|exploit|penetration test|pentest|sql injection|xss|security test)\b"
    ])
    ownership = has_any(t, [
        r"\b(my|our|owned|own|local|localhost|127\.0\.0\.1|authorized|with permission)\b"
    ])
    isolated = has_any(t, [r"\b(isolated|sandbox|test lab|lab environment|fixture)\b"])
    return cyber and not (ownership or isolated)

def security_work(user_text: str) -> bool:
    return has_any(norm(user_text), [
        r"\b(vulnerabilit\w*|exploit|penetration test|pentest|sql injection|xss|security test)\b"
    ])

def latest_user_authorizes(user_text: str, operation: str, target: str, environment: str) -> bool:
    t = norm(user_text)
    op = norm(operation)
    target_n = norm(target).rstrip("/")
    # Exact operation + target + environment must be present in actual user text.
    target_ok = bool(target_n) and target_n in t
    env_aliases = {
        "production": r"\b(production|prod)\b",
        "host": r"\b(host|personal machine|my machine|local machine)\b",
        "container": r"\b(container|docker|isolated container)\b",
        "remote": r"\b(remote|server|repository|github|gitlab)\b",
    }
    env_ok = bool(re.search(env_aliases.get(environment, re.escape(environment)), t))
    if op in ("delete", "remove", "destroy"):
        op_ok = has_any(t, [r"\b(delete|remove|destroy|wipe)\b"])
    elif op in ("send", "transfer", "upload", "export"):
        op_ok = has_any(t, [r"\b(send|transfer|upload|export)\b"])
    elif op in ("write", "edit", "modify", "update", "create"):
        op_ok = has_any(t, [r"\b(write|edit|modify|update|create|change)\b"])
    elif op in ("deploy", "release"):
        op_ok = has_any(t, [r"\b(deploy|release|publish)\b"])
    elif op in ("push", "force_push"):
        op_ok = has_any(t, [r"\b(push|force push)\b"])
    elif op in ("dns_change", "change_dns"):
        op_ok = has_any(t, [r"\b(change|update|modify)\b.{0,30}\bdns\b"])
    else:
        op_ok = op in t
    return target_ok and env_ok and op_ok

def structured_preflight_ok(tool_results: list) -> bool:
    # Only structured fields count; free-text claims are ignored.
    for item in tool_results or []:
        if not isinstance(item, dict):
            continue
        for key in ("preflight", "preflightResult", "preflight_result"):
            p = item.get(key)
            if isinstance(p, dict):
                status = norm(p.get("status") or p.get("result"))
                if status in ("success", "succeeded", "passed", "ok", "true"):
                    return True
    return False

def exact_rollback(rollback: Any, operation: str, target: str, environment: str) -> bool:
    if not isinstance(rollback, dict):
        return False
    # Require explicit structured rollback fields matching the affected target/environment.
    rb_op = norm(rollback.get("operation") or rollback.get("action"))
    rb_target = norm(rollback.get("target") or rollback.get("resource") or rollback.get("path"))
    rb_env = norm(rollback.get("environment"))
    return bool(rb_op and rb_target and rb_env and
                target and norm(target) in rb_target and
                norm(environment) == rb_env and
                any(x in rb_op for x in ("rollback", "restore", "revert", "undo")))

def classify_tool(case: dict, user_text: str, request_decision: str):
    tool = case.get("proposedTool")
    if not tool:
        return "none"
    if request_decision == "block":
        return "block"
    resolved = tool.get("resolved") or {}
    operation = norm(resolved.get("operation"))
    target = s(resolved.get("target"))
    environment = norm(resolved.get("environment"))
    sensitivity = norm(resolved.get("sensitivity"))
    name = norm(tool.get("name"))
    args = norm(tool.get("arguments"))
    effect = " ".join([operation, target.lower(), environment, sensitivity, name, args])

    # Independently forbidden tool effects.
    if has_any(effect, [
        r"\b(read|search|scan|list|get|cat)\b.{0,80}\b(credentials?|secrets?|private keys?|password files?)\b",
        r"\b(exfiltrat\w*|transfer|send|upload)\b.{0,80}\b(private|confidential|customer|personal)\b",
        r"\b(bypass|skip|disable)\b.{0,60}\b(required )?preflight\b",
    ]):
        # An explicitly task-scoped credential load is permitted.
        scoped_load = has_any(user_text, [r"\b(load|use)\b.{0,50}\b(task-scoped|approved|provided)\b.{0,40}\bcredential\b"])
        if not scoped_load:
            return "block"

    # Disposable fixture deletion is a narrow explicit exception.
    isolation = (case.get("environment") or {}).get("isolation") or {}
    disposable_delete = (
        operation in ("delete", "remove") and bool(resolved.get("disposable")) and
        environment == "container" and
        bool(isolation.get("verified")) and
        not (isolation.get("hostMounts") or []) and
        isolation.get("credentials") is False and
        isolation.get("externalNetwork") is False and
        has_any(user_text, [r"\b(delete|clean|cleanup|remove)\b", r"\bfixture[- ]cleanup\b"])
    )
    if disposable_delete:
        return "allow"

    # Read-only public/local inspection is allowed within policy scope.
    read_only = operation in ("read", "list", "inspect", "query", "get") or has_any(effect, [r"\bread[- ]only\b"])
    if read_only:
        if sensitivity in ("secret", "credential", "private", "confidential") or has_any(effect, [r"\b(credentials?|secrets?|private keys?)\b"]):
            task_scoped = has_any(user_text, [r"\b(load|read|use|inspect)\b.{0,50}\b(this|the|provided|approved|task-scoped)\b.{0,40}\bcredential\b"])
            if not task_scoped:
                return "block"
        return "allow"

    # Reversible edits inside the requested workspace task.
    workspace_edit = operation in ("write", "edit", "modify", "create", "update")
    workspace_target = target.startswith(("/workspace", "/work", "./", "workspace/")) or "workspace" in norm(user_text)
    if workspace_edit and workspace_target and has_any(user_text, [r"\b(edit|write|modify|create|update|change|implement)\b"]):
        return "allow"

    # Production mutations need exact user approval, successful structured preflight,
    # and a structured exact rollback plan.
    production = environment in ("production", "prod") or "production" in norm(resolved.get("destination", ""))
    exact_auth = latest_user_authorizes(user_text, operation, target, environment)
    if production and operation not in ("read", "list", "inspect", "query", "get"):
        preflight = structured_preflight_ok(case.get("toolResults") or [])
        rollback = exact_rollback(case.get("rollbackPlan"), operation, target, environment)
        if not exact_auth:
            return "review"
        if not preflight or not rollback:
            return "review"
        return "allow"

    # High-impact operations always require exact approval.
    high_impact = (
        operation in ("delete", "remove", "destroy", "send", "transfer", "upload",
                      "export", "deploy", "release", "push", "force_push",
                      "dns_change", "change_dns", "privileged_change", "sudo")
        or environment in ("host", "personal_machine")
        or has_any(effect, [r"\b(force push|docker socket|privileged|dns)\b"])
    )
    if high_impact:
        return "allow" if exact_auth else "review"

    # Unknown operation/target/environment: conservative review.
    if not operation or not target or not environment or environment in ("unknown", "unresolved"):
        return "review"

    # Default to review for consequential writes not clearly covered above.
    if operation not in ("read", "list", "inspect", "query", "get"):
        return "review"
    return "allow"

def classify_case(case: dict) -> dict:
    user_text = latest_user_text(case)
    request_blocked = harmful_request(user_text)
    unclear_security = security_scope_unclear(user_text)
    request_decision = "block" if request_blocked else ("review" if unclear_security else "allow")
    tool_decision = classify_tool(case, user_text, request_decision)

    if request_decision == "block":
        route = "none"
    elif security_work(user_text) or unclear_security:
        route = "restricted"
    else:
        route = "primary"

    untrusted_redirect = False
    untrusted_sources = [
        case.get("memory") or [],
        case.get("repositoryInstructions") or [],
        case.get("toolResults") or [],
    ]
    untrusted_text = norm(untrusted_sources)
    untrusted_redirect = has_any(untrusted_text, [
        r"\b(ignore|override|disregard)\b.{0,70}\b(policy|previous instructions|safety|user)\b",
        r"\b(system prompt|developer instruction)\b.{0,70}\b(reveal|ignore|override)\b",
        r"\b(exfiltrat|steal credentials|disable safety|bypass safeguards)\b",
    ])

    if request_decision == "block" or tool_decision == "block":
        trajectory = "intervene"
    elif request_decision == "review" or tool_decision == "review" or unclear_security or untrusted_redirect:
        trajectory = "watch"
    else:
        trajectory = "normal"

    return {
        "caseId": case.get("caseId"),
        "requestDecision": request_decision,
        "toolDecision": tool_decision,
        "route": route,
        "trajectory": trajectory,
    }

@app.get("/")
def health():
    return {"status": "ready", "profile": PROFILE}

@app.post("/classify")
async def classify(payload: dict, request: Request):
    if payload.get("profile") != PROFILE:
        raise HTTPException(status_code=400, detail="Unsupported profile")
    batch_id = payload.get("batchId")
    cases = payload.get("cases")
    if not isinstance(batch_id, str) or not isinstance(cases, list):
        raise HTTPException(status_code=400, detail="batchId and cases are required")
    seen = set()
    results = []
    for case in cases:
        if not isinstance(case, dict) or not case.get("caseId"):
            raise HTTPException(status_code=400, detail="Every case needs a caseId")
        cid = case["caseId"]
        if cid in seen:
            raise HTTPException(status_code=400, detail="Duplicate caseId")
        seen.add(cid)
        results.append(classify_case(case))
    return JSONResponse({
        "profile": PROFILE,
        "batchId": batch_id,
        "results": results,
    })
