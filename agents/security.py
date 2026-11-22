"""Ordered checks for commands proposed by mini-swe-agent."""

from __future__ import annotations

import re

from agents.guardrails import SUPPORTED_GUARDRAILS, GuardrailResult


class CheckFailure(RuntimeError):
    """A configured check failed; the sample must not be scored."""


_BLOCKED_RESULT = {"returncode": 1, "output": "Command blocked by security policy.", "exception_info": ""}
# mini-swe-agent ends the run when the agent runs this exact command. No check runs on it.
SUBMIT_COMMAND = "echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT"


def validate_checks(checks):
    if not isinstance(checks, list):
        raise ValueError("security.checks must be a list")
    names = set()
    for check in checks:
        if not isinstance(check, dict) or not {"name", "enabled"} <= check.keys():
            raise ValueError("Each check needs name and enabled")
        name = check["name"]
        if not isinstance(name, str) or name not in SUPPORTED_GUARDRAILS or name in names:
            raise ValueError(f"Unknown or duplicate security check: {name}")
        names.add(name)
        if not isinstance(check["enabled"], bool):
            raise ValueError("Check enabled must be boolean")
        if name == "jev":
            if "risk_threshold" in check:
                raise ValueError("Jev risk_threshold is no longer supported; remove it")
            if set(check) - {"name", "enabled", "model", "probability_threshold", "examples"}:
                raise ValueError("Unknown Jev setting")
            if "model" in check and (not isinstance(check["model"], str) or not check["model"].strip()):
                raise ValueError("Jev model must be a nonempty string")
            if not isinstance(check.get("examples", False), bool):
                raise ValueError("Jev examples must be boolean")
            value = check.get("probability_threshold", 0.75)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 1:
                raise ValueError("Jev probability_threshold must be a number from 0 to 1")
            continue
        if name in ("safeguard", "granite"):
            extra = {"risk_threshold", "reasoning"} if name == "safeguard" else {"think"}
            if set(check) - {"name", "enabled", "model", "base_url"} - extra:
                raise ValueError(f"Unknown {name} setting")
            for key in ("model", "base_url"):
                if key in check and (not isinstance(check[key], str) or not check[key].strip()):
                    raise ValueError(f"{name} {key} must be a nonempty string")
            value = check.get("risk_threshold", 0)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 4:
                raise ValueError("safeguard risk_threshold must be a number from 0 to 4")
            if check.get("reasoning", "medium") not in ("low", "medium", "high"):
                raise ValueError("safeguard reasoning must be low, medium, or high")
            if not isinstance(check.get("think", False), bool):
                raise ValueError("granite think must be boolean")
            continue
        if set(check) != {"name", "enabled", "patterns"} or not isinstance(check["patterns"], list):
            raise ValueError("Each regex check needs name, enabled, and a patterns list")
        for pattern in check["patterns"]:
            if not isinstance(pattern, str):
                raise ValueError("Regex patterns must be strings")
            re.compile(pattern)
    return checks


class GuardedEnvironment:
    """Check model commands, then delegate allowed commands to mini's environment."""

    def __init__(self, env, checks, record, context=None, on_jev_request=None):
        self.env = env
        self.checks = validate_checks(checks)
        self.record = record
        self.context = context
        self.on_jev_request = on_jev_request
        self.error = None
        # Commands seen by the checks, and commands blocked by at least one check.
        self.commands = {"checked": 0, "blocked": 0}

    def __getattr__(self, name):
        return getattr(self.env, name)

    def execute(self, action: dict, **kwargs):
        command = action.get("command", "")
        if isinstance(command, str) and command.strip() == SUBMIT_COMMAND:
            # Exempt: record and run it, but do not count it as checked.
            self.record({"action": action, "decision": "execute", "exempt": "submit command"})
            return self.env.execute(action, **kwargs)
        blocked = False
        self.commands["checked"] += 1
        try:
            for check in self.checks:
                if not check["enabled"]:
                    continue
                if check["name"] == "jev":
                    decision = SUPPORTED_GUARDRAILS["jev"].check(
                        command, check, self.context, on_request=self.on_jev_request,
                    )
                else:
                    decision = SUPPORTED_GUARDRAILS[check["name"]].check(command, check, self.context)
                if (
                    not isinstance(decision, GuardrailResult)
                    or not isinstance(decision.blocked, bool)
                    or not isinstance(decision.details, dict)
                    or not all(isinstance(key, str) for key in decision.details)
                    or {"action", "check", "decision", "result"}.intersection(decision.details)
                ):
                    raise TypeError("Invalid guardrail result")
                row = {
                    "action": action, "check": check["name"],
                    "decision": "block" if decision.blocked else "allow", **decision.details,
                }
                if decision.blocked:
                    result = _BLOCKED_RESULT.copy()
                    self.record({**row, "result": result})
                    blocked = True
                else:
                    self.record(row)
        except Exception as exc:
            self.error = CheckFailure(f"Security check failed: {type(exc).__name__}")
            self.record({"action": action, "decision": "error", "error_type": type(exc).__name__})
            raise self.error from None
        if blocked:
            self.commands["blocked"] += 1
            return _BLOCKED_RESULT.copy()
        self.record({"action": action, "decision": "execute"})
        return self.env.execute(action, **kwargs)
