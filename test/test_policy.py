import copy
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import check_policy  # noqa: E402

SAFE_PR = {
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/heads/feature/x",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [
            {"owner": "actions", "name": "checkout", "ref": "v4"},
            {"owner": "someorg", "name": "someaction", "ref": "a" * 40},
        ],
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "buildkit",
        "criticalVulnerabilities": 0,
        "digestPinned": True,
    },
}


def clone():
    return copy.deepcopy(SAFE_PR)


def test_safe_pr_promotes():
    assert check_policy(SAFE_PR) == []


def test_excess_permission_extra_key():
    p = clone()
    p["workflow"]["permissions"]["actions"] = "write"
    assert "EXCESS_PERMISSION" in check_policy(p)


def test_excess_permission_wrong_value():
    p = clone()
    p["workflow"]["permissions"]["id-token"] = "write"
    assert check_policy(p) == ["EXCESS_PERMISSION"]


def test_unsafe_pr_trigger():
    p = clone()
    p["workflow"]["trigger"] = "pull_request_target"
    assert check_policy(p) == ["UNSAFE_PR_TRIGGER"]


def test_tests_incomplete_matrix():
    p = clone()
    p["workflow"]["matrixComplete"] = False
    assert check_policy(p) == ["TESTS_INCOMPLETE"]


def test_tests_incomplete_failfast():
    p = clone()
    p["workflow"]["failFast"] = True
    assert check_policy(p) == ["TESTS_INCOMPLETE"]


def test_tests_incomplete_not_passed():
    p = clone()
    p["workflow"]["testsPassed"] = False
    assert check_policy(p) == ["TESTS_INCOMPLETE"]


def test_mutable_action_tag():
    p = clone()
    p["workflow"]["actions"][1]["ref"] = "v1.2.3"
    assert check_policy(p) == ["MUTABLE_ACTION"]


def test_mutable_action_uppercase():
    p = clone()
    p["workflow"]["actions"][1]["ref"] = "A" * 40
    assert "MUTABLE_ACTION" in check_policy(p)


def test_mutable_action_short():
    p = clone()
    p["workflow"]["actions"][1]["ref"] = "a" * 39
    assert "MUTABLE_ACTION" in check_policy(p)


def test_actions_org_exempt():
    p = clone()
    p["workflow"]["actions"].append(
        {"owner": "actions", "name": "setup-node", "ref": "v4"}
    )
    assert check_policy(p) == []


def test_single_stage_image():
    p = clone()
    p["image"]["multiStage"] = False
    assert check_policy(p) == ["SINGLE_STAGE_IMAGE"]


def test_root_runtime():
    p = clone()
    p["image"]["runsAsRoot"] = True
    assert check_policy(p) == ["ROOT_RUNTIME"]


def test_secret_in_layer_arg():
    p = clone()
    p["image"]["secretMode"] = "arg"
    assert check_policy(p) == ["SECRET_IN_LAYER"]


def test_secret_in_layer_copy():
    p = clone()
    p["image"]["secretMode"] = "copy"
    assert check_policy(p) == ["SECRET_IN_LAYER"]


def test_secret_mode_none_ok():
    p = clone()
    p["image"]["secretMode"] = "none"
    assert check_policy(p) == []


def test_critical_cve():
    p = clone()
    p["image"]["criticalVulnerabilities"] = 2
    assert check_policy(p) == ["CRITICAL_CVE"]


def test_unpinned_image():
    p = clone()
    p["image"]["digestPinned"] = False
    assert check_policy(p) == ["UNPINNED_IMAGE"]


def _safe_prod():
    p = clone()
    p["target"] = "production"
    p["event"] = "push"
    p["ref"] = "refs/heads/main"
    p["workflow"]["trigger"] = "push"
    p["workflow"]["environmentApproval"] = True
    return p


def test_safe_production_promotes():
    assert check_policy(_safe_prod()) == []


def test_invalid_production_ref():
    p = _safe_prod()
    p["ref"] = "refs/heads/release"
    assert check_policy(p) == ["INVALID_PRODUCTION_REF"]


def test_approval_required_missing():
    p = _safe_prod()
    del p["workflow"]["environmentApproval"]
    assert check_policy(p) == ["APPROVAL_REQUIRED"]


def test_approval_required_false():
    p = _safe_prod()
    p["workflow"]["environmentApproval"] = False
    assert check_policy(p) == ["APPROVAL_REQUIRED"]


def test_multi_failure_combination():
    p = clone()
    p["workflow"]["trigger"] = "pull_request_target"
    p["workflow"]["permissions"]["id-token"] = "write"
    p["image"]["runsAsRoot"] = True
    p["image"]["criticalVulnerabilities"] = 5
    result = sorted(check_policy(p))
    expected = sorted(
        ["CRITICAL_CVE", "EXCESS_PERMISSION", "ROOT_RUNTIME", "UNSAFE_PR_TRIGGER"]
    )
    assert result == expected
