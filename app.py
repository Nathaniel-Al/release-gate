import os
import re

from flask import Flask, jsonify, request

app = Flask(__name__)

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_PERMS = {"contents": "read", "packages": "write", "id-token": "none"}


def check_policy(body: dict) -> list[str]:
    violations = []

    target = body.get("target")
    event = body.get("event")
    ref = body.get("ref")
    workflow = body.get("workflow") or {}
    image = body.get("image") or {}
    perms = workflow.get("permissions") or {}
    actions = workflow.get("actions") or []

    # 1. Exact least-privilege permissions, no extras, no substitutions.
    no_extra_keys = set(perms.keys()) == set(REQUIRED_PERMS.keys())
    values_match = all(perms.get(k) == v for k, v in REQUIRED_PERMS.items())
    if not no_extra_keys or not values_match:
        violations.append("EXCESS_PERMISSION")

    # 2. PR trigger must never be pull_request_target when running as a PR.
    trigger = workflow.get("trigger")
    is_unsafe_trigger = trigger == "pull_request_target" or (
        event == "pull_request" and trigger != "pull_request"
    )
    if is_unsafe_trigger:
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Full matrix must run to completion with tests passing, no fail-fast.
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Third-party actions must be pinned to a full 40-char lowercase SHA.
    #    Actions owned by "actions" may use a version tag instead.
    has_mutable_action = False
    for a in actions:
        if not a or a.get("owner") == "actions":
            continue
        if not SHA_RE.match(str(a.get("ref") or "")):
            has_mutable_action = True
            break
    if has_mutable_action:
        violations.append("MUTABLE_ACTION")

    # 5. Hardened image requirements.
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")
    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 6. Production requires push-to-main and explicit environment approval.
    if target == "production":
        if not (event == "push" and ref == "refs/heads/main"):
            violations.append("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return violations


@app.post("/release-gate")
def release_gate():
    body = request.get_json(force=True, silent=True) or {}
    violations = check_policy(body)
    return jsonify(
        {
            "decision": "promote" if not violations else "block",
            "violations": violations,
        }
    )


@app.get("/")
def index():
    return "release-gate policy service is up"


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port)
