"""
janitor.py — background task that sweeps the credential store for expired entries.

Runs every JANITOR_INTERVAL seconds (default: 30).
When it finds an active credential past its expiry time, it:
  1. Marks it as "expired" in the credential store
  2. Writes a credential_expired event to the audit log
  3. Optionally attaches a deny policy to the underlying IAM role

The credential store is an in-memory dict injected at startup.
In production this would be DynamoDB with a TTL attribute.
"""
import asyncio
import logging
import time
from typing import Callable

logger = logging.getLogger("janitor")


class CredentialJanitor:
    def __init__(
        self,
        credential_store: dict,
        audit_logger,
        check_interval: float = 30.0,
        on_expire: Callable | None = None,
    ):
        self.store = credential_store
        self.audit = audit_logger
        self.interval = check_interval
        self.on_expire = on_expire   # optional hook (e.g. attach deny policy)
        self._running = False

    async def run(self) -> None:
        self._running = True
        logger.info(f"Janitor started — checking every {self.interval}s")
        while self._running:
            await asyncio.sleep(self.interval)
            self._sweep()

    def stop(self) -> None:
        self._running = False

    def _sweep(self) -> None:
        now = time.time()
        expired_count = 0

        for cred_id, cred in list(self.store.items()):
            if cred["status"] == "active" and cred["expires_at"] <= now:
                cred["status"] = "expired"
                expired_count += 1

                self.audit.log_expired(
                    credential_id=cred_id,
                    agent_id=cred["agent_id"],
                    task_type=cred["task_type"],
                )

                if self.on_expire:
                    try:
                        self.on_expire(cred_id, cred)
                    except Exception as e:
                        logger.warning(f"on_expire hook failed for {cred_id}: {e}")

        if expired_count:
            logger.info(f"Janitor: expired {expired_count} credential(s)")

    def active_count(self) -> int:
        return sum(1 for c in self.store.values() if c["status"] == "active")

    def summary(self) -> dict:
        counts = {"active": 0, "expired": 0, "revoked": 0}
        for c in self.store.values():
            counts[c["status"]] = counts.get(c["status"], 0) + 1
        return counts
