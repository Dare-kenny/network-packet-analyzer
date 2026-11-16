"""
Reverse DNS lookups, off the request path.

A PTR lookup can take seconds, or hang on an unreachable resolver, so
resolving inside a request would stall the page that polls once a second.
Instead lookup() answers from cache immediately and queues anything it has
not seen; the name turns up on a later poll, which suits a UI that is
refreshing anyway.

Lookups go through the system resolver, so they stay on the machine's own
DNS and nothing about the capture is sent anywhere else. The queries do
tell that resolver which addresses are being looked at, which is why this
can be switched off with PACKET_ANALYZER_DNS=0.
"""

import os
import queue
import socket
import threading

# Worker threads are daemons and the queue is bounded, so a resolver that
# hangs costs a stalled lookup rather than a stalled process or unbounded
# memory.
DEFAULT_WORKERS = 4
DEFAULT_QUEUE_SIZE = 512


def system_resolve(ip):
    """PTR name for an address, or None. Never raises."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError, ValueError):
        return None


def enabled_by_environment(env=None):
    """Reverse DNS is on unless PACKET_ANALYZER_DNS is set to a false value."""
    raw = (env if env is not None else os.environ).get("PACKET_ANALYZER_DNS")

    if raw is None:
        return True

    return raw.strip().lower() not in ("0", "false", "no", "off", "")


class HostnameResolver:
    """
    Non-blocking reverse DNS with a cache that remembers misses.

    An address that has no PTR record is cached as a miss so it is looked
    up once rather than on every poll.
    """

    def __init__(
        self,
        resolve=None,
        workers=DEFAULT_WORKERS,
        max_queue=DEFAULT_QUEUE_SIZE,
        enabled=True,
        start=True,
    ):
        self.enabled = enabled
        self._resolve = resolve or system_resolve
        self._cache = {}
        self._queued = set()
        self._lock = threading.Lock()
        self._queue = queue.Queue(maxsize=max_queue)
        self._threads = []

        if start and enabled:
            self._start_workers(workers)

    def _start_workers(self, workers):
        for n in range(workers):
            thread = threading.Thread(
                target=self._worker,
                name="dns-resolver-%d" % n,
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def _worker(self):
        while True:
            ip = self._queue.get()
            try:
                self._resolve_into_cache(ip)
            finally:
                self._queue.task_done()

    def _resolve_into_cache(self, ip):
        name = self._resolve(ip)

        with self._lock:
            self._cache[ip] = name
            self._queued.discard(ip)

    def lookup(self, ip):
        """
        Cached hostname for an address, or None.

        None means "no name yet": either not looked up, still in flight, or
        the address genuinely has no PTR record. The caller shows the raw
        address either way, so the three cases need no distinction.
        """
        if not ip or not self.enabled:
            return None

        with self._lock:
            if ip in self._cache:
                return self._cache[ip]

            if ip in self._queued:
                return None

            self._queued.add(ip)

        try:
            self._queue.put_nowait(ip)
        except queue.Full:
            # Dropped rather than queued: forget it so a later poll can
            # try again once the backlog has cleared.
            with self._lock:
                self._queued.discard(ip)

        return None

    def drain(self):
        """
        Resolve everything queued, synchronously.

        For tests and for any caller that wants names now rather than on
        the next poll.
        """
        while True:
            try:
                ip = self._queue.get_nowait()
            except queue.Empty:
                return

            try:
                self._resolve_into_cache(ip)
            finally:
                self._queue.task_done()

    def cached(self):
        """A copy of the cache, for tests and diagnostics."""
        with self._lock:
            return dict(self._cache)


def annotate(rows, resolver, fields=("host",)):
    """
    Add a resolved name beside each address field, in place.

    ``host`` gains ``host_name``. A row whose address has no name yet gets
    None, so the shape of the payload never changes between polls.
    """
    for row in rows:
        for field in fields:
            address = row.get(field)
            row[field + "_name"] = resolver.lookup(address) if address else None

    return rows
