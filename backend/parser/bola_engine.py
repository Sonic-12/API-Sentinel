
from collections import deque, OrderedDict
import time

BOLA_RISK_BASE = 60
BOLA_RISK_STEP = 15
BOLA_RISK_MAX = 100

DEFAULT_WINDOW = 20          # max object_ids remembered per token
DEFAULT_UNIQUE_THRESHOLD = 3  # distinct *foreign* objects before alert
DEFAULT_TTL_SECONDS = 900     # evict a token's history after 15 min idle
DEFAULT_MAX_TOKENS = 5000     # hard cap on tracked tokens (LRU evict)


class BolaEngine:
    def __init__(
        self,
        unique_threshold=DEFAULT_UNIQUE_THRESHOLD,
        window=DEFAULT_WINDOW,
        ttl_seconds=DEFAULT_TTL_SECONDS,
        max_tokens=DEFAULT_MAX_TOKENS,
        clock=time.time,
    ):
        self.unique_threshold = unique_threshold
        self.window = window
        self.ttl_seconds = ttl_seconds
        self.max_tokens = max_tokens
        self._clock = clock
        # token -> {"owner_id": obj, "seen": set(), "recent": deque, "last_seen": ts}
        self._history = OrderedDict()

    def _evict_stale(self, now):
        stale = [
            tok for tok, rec in self._history.items()
            if now - rec["last_seen"] > self.ttl_seconds
        ]
        for tok in stale:
            del self._history[tok]

    def _get_record(self, token, now):
        if token in self._history:
            rec = self._history[token]
            self._history.move_to_end(token)
            return rec

        if len(self._history) >= self.max_tokens:
            self._history.popitem(last=False)  # drop least-recently-used

        rec = {
            "owner_id": None,
            "seen": set(),
            "recent": deque(maxlen=self.window),
            "last_seen": now,
        }
        self._history[token] = rec
        return rec

    def evaluate(self, authorization, object_id, parsed_request):
        """Update state for this request and, if warranted, raise a
        BOLA alert on parsed_request. Returns the current foreign-object
        count for this token (0 if no signal)."""
        if object_id is None or not authorization:
            return 0

        now = self._clock()
        self._evict_stale(now)

        rec = self._get_record(authorization, now)
        rec["last_seen"] = now

        if rec["owner_id"] is None:
            rec["owner_id"] = object_id  # baseline: first object == "self"

        rec["recent"].append(object_id)
        rec["seen"].add(object_id)

        foreign_ids = rec["seen"] - {rec["owner_id"]}
        foreign_count = len(foreign_ids)

        if foreign_count >= self.unique_threshold:
            risk = min(
                BOLA_RISK_BASE + BOLA_RISK_STEP * (foreign_count - self.unique_threshold),
                BOLA_RISK_MAX,
            )
            parsed_request.risk_score += risk
            parsed_request.alerts.append(
                f"Possible BOLA Attack: token baselined to object "
                f"'{rec['owner_id']}' also accessed {foreign_count} other "
                f"object IDs ({sorted(foreign_ids, key=str)[:5]})"
            )

        return foreign_count

    def reset(self):
        self._history.clear()