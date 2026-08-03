from collections import deque, OrderedDict
import re
import time

RATE_RISK_BASE = 40
RATE_RISK_STEP = 10
RATE_RISK_MAX = 100
DEFAULT_WINDOW_SECONDS = 10
DEFAULT_MAX_REQUESTS = 8
DEFAULT_TTL_SECONDS = 900
DEFAULT_MAX_IDENTITIES = 5000

_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_ID_SEGMENT = re.compile(rf"^\d+$|^{_UUID}$")


def _path_template(path: str) -> str:
    segments = path.strip("/").split("/")
    return "/" + "/".join("{id}" if _ID_SEGMENT.match(s) else s for s in segments)


class RateLimiter:
    def __init__(self, window_seconds=DEFAULT_WINDOW_SECONDS, max_requests=DEFAULT_MAX_REQUESTS,
                 ttl_seconds=DEFAULT_TTL_SECONDS, max_identities=DEFAULT_MAX_IDENTITIES, clock=time.time):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self.ttl_seconds = ttl_seconds
        self.max_identities = max_identities
        self._clock = clock
        self._history = OrderedDict()

    def _evict_stale(self, now):
        stale_identities = []
        for ident, flows in self._history.items():
            stale_flows = [f for f, rec in flows.items() if now - rec["last_seen"] > self.ttl_seconds]
            for f in stale_flows:
                del flows[f]
            if not flows:
                stale_identities.append(ident)
        for ident in stale_identities:
            del self._history[ident]

    def _get_flow_record(self, identity, flow, now):
        if identity in self._history:
            self._history.move_to_end(identity)
        else:
            if len(self._history) >= self.max_identities:
                self._history.popitem(last=False)
            self._history[identity] = {}
        flows = self._history[identity]
        if flow not in flows:
            flows[flow] = {"timestamps": deque(), "last_seen": now}
        return flows[flow]

    def evaluate(self, identity, path, parsed_request):
        client_ip = getattr(parsed_request, "client_ip", "unknown")
        key = identity or f"anon:{client_ip}"
        flow = _path_template(path)
        now = self._clock()

        self._evict_stale(now)
        rec = self._get_flow_record(key, flow, now)
        rec["last_seen"] = now

        ts = rec["timestamps"]
        ts.append(now)
        while ts and now - ts[0] > self.window_seconds:
            ts.popleft()

        count = len(ts)
        if count > self.max_requests:
            risk = min(RATE_RISK_BASE + RATE_RISK_STEP * (count - self.max_requests), RATE_RISK_MAX)
            parsed_request.risk_score += risk
            parsed_request.alerts.append(
                f"Possible Bot / Rate Abuse: {count} requests to '{flow}' from '{key}' "
                f"within {self.window_seconds}s"
            )
        return count

    def reset(self):
        self._history.clear()