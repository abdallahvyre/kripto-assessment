"""Versioned trusted Python extensions. This interface is not a security sandbox."""
from __future__ import annotations

import importlib.util
import json
import re
import sys
import time
from pathlib import Path

from core.evidence import serialize
from core.http import RateLimitedSession
from core.redact import redact_text

API_VERSION = 1


class PluginError(ValueError):
    pass


def discover(directory):
    root = Path(directory).resolve()
    manifests, errors = {}, []
    if not root.is_dir():
        raise PluginError("plugin directory does not exist")
    for path in sorted(root.glob("*/plugin.json")):
        try:
            if path.is_symlink() or path.parent.is_symlink() or path.stat().st_size > 16000:
                raise PluginError("plugin manifest is linked or oversized")
            data = json.loads(path.read_text(encoding="utf-8"))
            key = data["id"]
            if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", key):
                raise PluginError("invalid plugin ID")
            if key in manifests:
                raise PluginError("duplicate plugin ID")
            if data.get("api_version") != API_VERSION:
                raise PluginError("incompatible plugin API version")
            if not isinstance(data.get("name"), str) or not isinstance(data.get("version"), str):
                raise PluginError("name and version are required")
            if not isinstance(data.get("passive"), bool):
                raise PluginError("passive must be an explicit boolean")
            minimum = tuple(map(int, data.get("min_python", "3.10").split(".")))
            if sys.version_info[:len(minimum)] < minimum:
                raise PluginError("plugin requires a newer Python runtime")
            source = (path.parent / "plugin.py").resolve()
            if source.parent != path.parent.resolve() or not source.is_file():
                raise PluginError("plugin source escapes its directory or is missing")
            manifests[key] = dict(data, source=str(source))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append({"manifest": str(path), "error": redact_text(exc)})
    return manifests, errors


class PluginContext:
    def __init__(self, target, policy, control, metadata, snapshot, budget=100, seconds=15):
        self.target, self.policy, self.control = target, policy, control
        self.metadata = dict(metadata)
        self.snapshot = json.loads(serialize(snapshot))
        self.logs, self.requests = [], 0
        self._budget, self._deadline = budget, time.monotonic() + seconds
        self._session = RateLimitedSession(policy=policy)

    def check(self):
        if self.control:
            self.control.check()
        if time.monotonic() > self._deadline:
            raise PluginError("cooperative plugin deadline exceeded")

    def request(self, method, url, **kwargs):
        self.check()
        if self.metadata["passive"]:
            raise PluginError("passive plugins cannot send requests")
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            raise PluginError("plugin interface permits read-only HTTP methods only")
        if set(kwargs) - {"params", "headers", "timeout", "allow_redirects"}:
            raise PluginError("plugin request option is not permitted")
        if self.requests >= self._budget:
            raise PluginError("plugin request budget exceeded")
        kwargs["timeout"] = min(float(kwargs.get("timeout", 6)), 6)
        self.requests += 1
        return self._session.request(method, url, **kwargs)

    def log(self, message):
        self.logs.append(redact_text(message)[:500])
        del self.logs[:-100]

    def close(self):
        self._session.close()


class PluginRegistry:
    def __init__(self, directory=None):
        self.manifests, self.errors = discover(directory) if directory else ({}, [])

    def run(self, enabled, disabled, target, policy, control, snapshot, mode="safe", authorized=False):
        outcomes = {}
        for key in dict.fromkeys(enabled or []):
            if key in (disabled or []):
                outcomes[key] = {"state": "SKIPPED", "reason": "disabled by operator"}
                continue
            metadata = self.manifests.get(key)
            if metadata is None:
                outcomes[key] = {"state": "FAILED", "error": "plugin not registered"}
                continue
            if not metadata["passive"] and (mode == "safe" or not authorized):
                outcomes[key] = {"state": "SKIPPED", "reason": "active plugin requires authorized active mode"}
                continue
            context, module, started = None, None, time.monotonic()
            outcome = {"state": "OK", "findings": [], "metadata": {k: v for k, v in metadata.items() if k != "source"}}
            try:
                context = PluginContext(target, policy, control, metadata, snapshot)
                spec = importlib.util.spec_from_file_location("kripto_plugin_" + key, metadata["source"])
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if not callable(getattr(module, "run", None)):
                    raise PluginError("plugin must define run(context)")
                if callable(getattr(module, "initialize", None)):
                    module.initialize(context)
                entries = module.run(context)
                for item in entries or []:
                    context.check()
                    if len(outcome["findings"]) >= 200:
                        raise PluginError("plugin finding limit reached")
                    item = json.loads(serialize(item, limit=32000))
                    if not isinstance(item, dict) or not item.get("kind") or not item.get("title"):
                        raise PluginError("plugin finding requires kind and title")
                    item.setdefault("target", target)
                    policy.authorize(item["target"], method=item.get("method", "GET"), source="plugin-finding")
                    item.setdefault("verification", "POTENTIAL")
                    outcome["findings"].append(item)
                context.check()
            except Exception as exc:
                outcome.update(state="FAILED", error=redact_text(f"{type(exc).__name__}: {exc}"))
            finally:
                if context:
                    try:
                        if callable(getattr(module, "cleanup", None)):
                            module.cleanup(context)
                    except Exception as exc:
                        outcome.update(state="FAILED", cleanup_error=redact_text(exc))
                    context.close()
                    outcome.update(logs=context.logs, requests=context.requests)
                outcome["elapsed_seconds"] = round(time.monotonic() - started, 3)
            outcomes[key] = outcome
        return {"plugins": outcomes, "discovery_errors": self.errors,
                "trust_model": "Trusted in-process Python code; capability interface is not a sandbox. Deadlines are cooperative."}
