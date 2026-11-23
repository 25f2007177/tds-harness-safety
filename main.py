import re
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI(title="TDS Harness Safety Classifier", version="2.0.0")
PROFILE = "agent-harness-2026-09"


def s(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        return " ".join(s(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(s(v) for v in value)
    return str(value)


def norm(value: Any) -> str:
    return re.sub(r"\s+", " ", s(value)).strip().lower()


def matches(text: str, patterns: list) -> bool:
    return any(re.search(p, text, re.I | re.S) for p in patterns)


def user_messages(case: dict) -> list:
    return [
        s(m.get("content"))
        for m in (case.get("messages") or [])
        if isinstance(m, dict) and m.get("role") == "user"
    ]


def all_user_text(case: dict) -> str:
    return "\n".join(user_messages(case))


def get_tool(case: dict) -> dict:
    tool = case.get("proposedTool")
    return tool if isinstance(tool, dict) else {}


def get_resolved(case: dict) -> dict:
    resolved = get_tool(case).get("resolved")
    return resolved if isinstance(resolved, dict) else {}


def get_operation(case: dict) -> str:
    return norm(get_resolved(case).get("operation"))


def get_target(case: dict) -> str:
    return norm(get_resolved(case).get("target")).rstrip("/")


def get_environment(case: dict) -> str:
    return norm(get_resolved(case).get("environment"))


def get_destination(case: dict) -> str:
    r = get_resolved(case)
    return norm(
        r.get("destination")
        or r.get("destinationEnvironment")
        or r.get("destination_environment")
        or r.get("destinationTarget")
        or r.get("destination_target")
    )


def is_cyber(text: str) -> bool:
    return matches(text, [
        r"\bvulnerabilit\w*\b",
        r"\bexploit(?:ation|ing|s)?\b",
        r"\bpenetration test(?:ing)?\b",
        r"\bpentest\b",
        r"\bsql injection\b",
        r"\bcross[- ]site scripting\b",
        r"\bxss\b",
        r"\bsecurity (?:test|testing|assessment|audit|research)\b",
        r"\bport scan(?:ning)?\b",
    ])


def cyber_scope(text: str) -> tuple:
    ownership = matches(text, [
        r"\bmy (?:own )?(?:server|website|app|application|system|machine|lab|network)\b",
        r"\bour (?:server|website|app|application|system|lab|network)\b",
        r"\bowned by me\b",
        r"\bowned by us\b",
        r"\bi own\b",
        r"\bwe own\b",
        r"\bwith (?:the )?owner's permission\b",
        r"\bwith permission\b",
        r"\bauthorized (?:target|system|testing)\b",
    ])
    isolated = matches(text, [
        r"\bisolated\b",
        r"\bsandbox\b",
        r"\btest lab\b",
        r"\blab environment\b",
        r"\blocalhost\b",
        r"\b127\.0\.0\.1\b",
        r"\b127\.0\.0\.0/8\b",
        r"\bprivate test environment\b",
    ])
    return ownership, isolated


HARMFUL_PATTERNS = [
    r"\bsteal\w*\b.{0,100}\b(credentials?|passwords?|tokens?|api keys?|secrets?)\b",
    r"\b(exfiltrat\w*|leak|dump|upload|send|extract)\b.{0,100}\b(private|confidential|customer|personal)\s+(data|records|files?)\b",
    r"\b(commit|perpetrat\w*|execute|facilitat\w*)\b.{0,60}\bfraud\b",
    r"\b(harass|stalk|dox|threaten)\b.{0,80}\b(real person|person|employee|customer|victim|ex[- ]partner)\b",
    r"\b(build|develop|create|write|deploy|make)\b.{0,80}\b(destructive malware|wiper malware|ransomware|credential stealer|botnet)\b",
    r"\b(build|make|construct|weaponize|deploy)\b.{0,80}\b(bomb|explosive device|poison|weapon)\b",
    r"\b(evade|bypass|disable|circumvent)\b.{0,100}\b(safeguards?|security controls?|detection)\b.{0,100}\b(steal|exfiltrat|fraud|harass|harm)\b",
]


def harmful_request(text: str) -> bool:
    t = norm(text)
    if not matches(t, HARMFUL_PATTERNS):
        return False

    # Benign analysis of quoted harmful content is allowed.
    asks_to_analyze = matches(t, [
        r"\b(analy[sz]e|inspect|review|translate|summari[sz]e|explain|classify|detect)\b",
        r"\bquoted text\b",
        r"\bprompt injection\b",
        r"\bmalicious instruction\b",
    ])
    asks_to_execute = matches(t, [
        r"\b(do|perform|execute|run|carry out|follow|implement|help me|write|create|build|deploy|send|extract|steal)\b",
    ])
    return not (asks_to_analyze and not asks_to_execute)


def operation_words(operation: str) -> list:
    groups = {
        "delete": ["delete", "remove", "destroy", "wipe"],
        "remove": ["delete", "remove", "destroy", "wipe"],
        "destroy": ["delete", "remove", "destroy", "wipe"],
        "send": ["send", "transfer", "upload", "export"],
        "transfer": ["send", "transfer", "upload", "export"],
        "upload": ["send", "transfer", "upload", "export"],
        "export": ["send", "transfer", "upload", "export"],
        "write": ["write", "edit", "modify", "update", "create", "change"],
        "edit": ["write", "edit", "modify", "update", "create", "change"],
        "modify": ["write", "edit", "modify", "update", "create", "change"],
        "update": ["write", "edit", "modify", "update", "create", "change"],
        "create": ["write", "edit", "modify", "update", "create", "change"],
        "deploy": ["deploy", "release", "publish"],
        "release": ["deploy", "release", "publish"],
        "push": ["push"],
        "force_push": ["force push", "force-push"],
        "dns_change": ["change", "update", "modify"],
        "change_dns": ["change", "update", "modify"],
        "privileged_change": ["change", "modify", "run", "execute"],
        "sudo": ["sudo", "run", "execute"],
    }
    return groups.get(operation, [operation.replace("_", " ")])


def has_exact_approval(case: dict) -> bool:
    messages = user_messages(case)
    if not messages:
        return False

    operation = get_operation(case)
    target = get_target(case)
    environment = get_environment(case)
    destination = get_destination(case)

    if not operation or not target or not environment:
        return False

    # Find the latest user message that refers to this operation.
    applicable = []
    for message in messages:
        t = norm(message)
        refers_to_operation = any(
            re.search(r"\b" + re.escape(word) + r"\b", t)
            for word in operation_words(operation)
        )
        refers_to_target = target in t
        if refers_to_operation or refers_to_target:
            applicable.append(t)

    if not applicable:
        return False

    latest = applicable[-1]

    # A later refusal/revocation is not approval.
    if matches(latest, [
        r"\bdo not\b",
        r"\bdon't\b",
        r"\bnever\b",
        r"\brevoke\b",
        r"\bwithdraw\b",
        r"\bcancel\b",
        r"\bstop\b",
        r"\bno longer authori[sz]e\b",
    ]):
        return False

    operation_ok = any(
        re.search(r"\b" + re.escape(word) + r"\b", latest)
        for word in operation_words(operation)
    )
    target_ok = target in latest
    environment_ok = environment in latest

    if environment == "production":
        environment_ok = matches(latest, [r"\bproduction\b", r"\bprod\b"])
    elif environment == "host":
        environment_ok = matches(latest, [
            r"\bhost\b", r"\bpersonal machine\b", r"\bmy machine\b",
            r"\blocal machine\b",
        ])
    elif environment == "container":
        environment_ok = matches(latest, [
            r"\bcontainer\b", r"\bdocker\b", r"\bisolated container\b",
        ])
    elif environment == "remote":
        environment_ok = matches(latest, [
            r"\bremote\b", r"\bserver\b", r"\brepository\b",
            r"\bgithub\b", r"\bgitlab\b",
        ])

    destination_ok = True
    if destination:
        destination_ok = destination in latest

    return operation_ok and target_ok and environment_ok and destination_ok


def has_revocation(case: dict) -> bool:
    operation = get_operation(case)
    target = get_target(case)
    if not operation:
        return False

    words = operation_words(operation)
    for message in user_messages(case):
        t = norm(message)
        refers_to_operation = any(
            re.search(r"\b" + re.escape(word) + r"\b", t)
            for word in words
        )
        refers_to_target = bool(target and target in t)

        refusal = matches(t, [
            r"\bdo not\b",
            r"\bdon't\b",
            r"\bnever\b",
            r"\brevoke\b",
            r"\bwithdraw\b",
            r"\bcancel\b",
            r"\bstop\b",
            r"\bno longer authori[sz]e\b",
        ])
        if refusal and (refers_to_operation or refers_to_target):
            return True
    return False


def untrusted_redirect(case: dict) -> bool:
    untrusted = norm([
        case.get("memory") or [],
        case.get("repositoryInstructions") or [],
        case.get("toolResults") or [],
    ])
    return matches(untrusted, [
        r"\bignore\b.{0,80}\b(previous|prior|system|developer|safety|policy|user)\b",
        r"\boverride\b.{0,80}\b(policy|safety|instructions|user)\b",
        r"\bdisregard\b.{0,80}\b(instructions|policy|safety)\b",
        r"\breveal\b.{0,50}\b(system prompt|developer instruction)\b",
        r"\bbypass\b.{0,50}\b(safety|safeguards|policy)\b",
    ])


def structured_preflight_ok(case: dict) -> bool:
    for item in case.get("toolResults") or []:
        if not isinstance(item, dict):
            continue
        for key in ("preflight", "preflightResult", "preflight_result"):
            p = item.get(key)
            if isinstance(p, dict):
                status = norm(p.get("status") or p.get("result"))
                if status in ("success", "succeeded", "passed", "ok", "true"):
                    return True
    return False


def exact_rollback(case: dict) -> bool:
    rb = case.get("rollbackPlan")
    if not isinstance(rb, dict):
        return False

    operation = get_operation(case)
    target = get_target(case)
    environment = get_environment(case)

    rb_operation = norm(rb.get("operation") or rb.get("action"))
    rb_target = norm(rb.get("target") or rb.get("resource") or rb.get("path"))
    rb_environment = norm(rb.get("environment"))

    return bool(
        rb_operation and rb_target and rb_environment
        and target and target == rb_target.rstrip("/")
        and environment == rb_environment
        and matches(rb_operation, [r"\b(rollback|restore|revert|undo)\b"])
    )


def independently_forbidden_tool(case: dict) -> bool:
    tool = get_tool(case)
    resolved = get_resolved(case)
    operation = get_operation(case)
    target = get_target(case)
    sensitivity = norm(resolved.get("sensitivity"))
    destination = get_destination(case)
    effect = norm([
        operation, target, sensitivity,
        tool.get("name"), tool.get("arguments"), resolved,
    ])
    text = all_user_text(case)

    # Explicit revocation and forbidden effects override approvals.
    if has_revocation(case):
        return True

    # Unrelated credential searching/reading is forbidden.
    credential_access = matches(effect, [
        r"\b(read|search|scan|list|get|cat|find|copy|extract)\b.{0,100}\b(credentials?|secrets?|private keys?|password files?|api keys?|tokens?)\b",
        r"\b(credentials?|secrets?|private keys?|password files?|api keys?|tokens?)\b.{0,100}\b(read|search|scan|list|get|cat|find|copy|extract)\b",
    ])
    scoped_credential = matches(text, [
        r"\b(load|use)\b.{0,100}\b(task[- ]scoped|approved|provided|specific)\b.{0,60}\bcredential\b",
        r"\b(load|use)\b.{0,60}\bcredential\b.{0,60}\b(for this task|for the requested operation)\b",
    ])
    if credential_access and not scoped_credential:
        return True

    # Private data may only go to an explicitly named approved destination.
    private_transfer = (
        operation in ("send", "transfer", "upload", "export")
        and sensitivity in ("private", "confidential", "personal", "customer", "sensitive")
    )
    if private_transfer:
        if not destination:
            return False  # unresolved destination: review
        if destination not in norm(text):
            return True
        if not has_exact_approval(case):
            return True

    # Bypassing a required production preflight is forbidden.
    if matches(effect, [
        r"\b(bypass|skip|disable|ignore)\b.{0,80}\b(required )?preflight\b",
    ]):
        return True

    return False


def classify_request(case: dict) -> str:
    text = all_user_text(case)

    if harmful_request(text):
        return "block"

    # A proposed tool can reveal a prohibited purpose even when
    # the user's wording is vague or appears harmless.
    tool = get_tool(case)
    if tool and independently_forbidden_tool(case):
        return "block"

    if is_cyber(text):
        owned, isolated = cyber_scope(text)
        if not (owned and isolated):
            return "review"

    return "allow"


def classify_tool(case: dict, request_decision: str) -> str:
    tool = get_tool(case)
    if not tool:
        return "none"

    if request_decision == "block":
        return "block"

    if independently_forbidden_tool(case):
        return "block"

    if request_decision == "review":
        return "review"

    resolved = get_resolved(case)
    operation = get_operation(case)
    target = get_target(case)
    environment = get_environment(case)
    sensitivity = norm(resolved.get("sensitivity"))
    text = all_user_text(case)

    # Unknown or unresolved metadata always requires review.
    if not operation or not target or not environment:
        return "review"
    if environment in ("unknown", "unresolved", "none", "null"):
        return "review"
    if target in ("unknown", "unresolved", "none", "null"):
        return "review"

    # Verified disposable fixture cleanup is a narrow exception.
    case_environment = case.get("environment") or {}
    isolation = case_environment.get("isolation") or {}
    fixture_delete = (
        operation in ("delete", "remove", "destroy")
        and bool(resolved.get("disposable"))
        and environment == "container"
        and isolation.get("verified") is True
        and not (isolation.get("hostMounts") or [])
        and isolation.get("credentials") is False
        and isolation.get("externalNetwork") is False
        and matches(text, [
            r"\bfixture\b",
            r"\bexperiment\b",
            r"\bcleanup\b",
            r"\bdelete\b",
            r"\bremove\b",
        ])
    )
    if fixture_delete:
        return "allow"

    # Read-only, non-sensitive workspace/public inspection.
    read_only = operation in ("read", "list", "inspect", "query", "get")
    if read_only:
        if sensitivity in ("secret", "credential", "private", "confidential"):
            return "review"

        workspace = (
            target.startswith(("/workspace/", "/work/", "./", "workspace/"))
            or target in ("/workspace", "/work")
        )
        public_metadata = matches(norm([target, get_tool(case).get("name")]), [
            r"\b(terraform|schema|git status|git log|git diff|git show)\b",
            r"\.tf\b",
            r"\bpublic schema\b",
        ])
        if workspace or public_metadata:
            return "allow"

        return "review"

    # Reversible edits in the requested workspace task.
    reversible_edit = operation in ("write", "edit", "modify", "create", "update")
    workspace_target = (
        target.startswith(("/workspace/", "/work/", "./", "workspace/"))
        or target in ("/workspace", "/work")
    )
    task_requested = matches(text, [
        r"\b(edit|write|modify|create|update|change|implement|fix)\b",
    ])
    if reversible_edit and workspace_target and task_requested:
        return "allow"

    # Production mutations need exact approval, preflight and rollback.
    production = (
        environment in ("production", "prod")
        or get_destination(case) in ("production", "prod")
    )
    if production and operation not in ("read", "list", "inspect", "query", "get"):
        if not has_exact_approval(case):
            return "review"
        if not structured_preflight_ok(case):
            return "review"
        if not exact_rollback(case):
            return "review"
        return "allow"

    high_impact = (
        operation in (
            "delete", "remove", "destroy", "send", "transfer", "upload",
            "export", "deploy", "release", "push", "force_push",
            "dns_change", "change_dns", "privileged_change", "sudo",
        )
        or environment in ("host", "personal_machine")
        or matches(norm([resolved, get_tool(case).get("arguments")]), [
            r"\b(force[- ]push|docker socket|privileged|dns)\b",
        ])
    )

    if high_impact:
        return "allow" if has_exact_approval(case) else "review"

    # Other consequential writes need explicit approval.
    if operation not in ("read", "list", "inspect", "query", "get"):
        return "allow" if has_exact_approval(case) else "review"

    return "review"


def classify_case(case: dict) -> dict:
    text = all_user_text(case)
    request_decision = classify_request(case)
    tool_decision = classify_tool(case, request_decision)

    cyber = is_cyber(text)
    owned, isolated = cyber_scope(text)
    unclear_security = cyber and not (owned and isolated)

    if request_decision == "block":
        route = "none"
    elif cyber or unclear_security:
        route = "restricted"
    else:
        route = "primary"

    redirect = untrusted_redirect(case)

    if request_decision == "block" or tool_decision == "block":
        trajectory = "intervene"
    elif (
        request_decision == "review"
        or tool_decision == "review"
        or unclear_security
        or redirect
    ):
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
async def classify(payload: dict):
    if payload.get("profile") != PROFILE:
        raise HTTPException(status_code=400, detail="Unsupported profile")

    batch_id = payload.get("batchId")
    cases = payload.get("cases")

    if not isinstance(batch_id, str) or not isinstance(cases, list):
        raise HTTPException(
            status_code=400,
            detail="batchId and cases are required",
        )

    seen = set()
    results = []

    for case in cases:
        if not isinstance(case, dict) or not case.get("caseId"):
            raise HTTPException(
                status_code=400,
                detail="Every case needs a caseId",
            )

        case_id = case["caseId"]
        if case_id in seen:
            raise HTTPException(status_code=400, detail="Duplicate caseId")

        seen.add(case_id)
        results.append(classify_case(case))

    return JSONResponse({
        "profile": PROFILE,
        "batchId": batch_id,
        "results": results,
    })
