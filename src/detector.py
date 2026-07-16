import json
import threading
import time
from collections import defaultdict
from datetime import timedelta, datetime, timezone

TIME_WINDOW = timedelta(seconds=60)
THRESHOLD = 5
POLL_INTERVAL = 5
MAX_EVENTS_KEPT = 300

_lock = threading.Lock()
_state = {
    "status": "starting",
    "message": "",
    "started_at": None,
    "last_updated": None,
    "threshold": THRESHOLD,
    "window_seconds": int(TIME_WINDOW.total_seconds()),
    "events": [],
    "active": {},
}


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _write_logs_json(path):
    with _lock:
        with open(path, "w") as f:
            json.dump(_state, f, indent=2, default=str)


def _record_event(username, ip_addr, logon_type, event_time, attempts, alert):
    entry = {
        "timestamp": str(event_time),
        "username": username,
        "ip": ip_addr,
        "logon_type": logon_type,
        "attempts": attempts,
        "alert": alert,
    }
    with _lock:
        _state["events"].insert(0, entry)
        _state["events"] = _state["events"][:MAX_EVENTS_KEPT]

        key = f"{username}@{ip_addr}"
        _state["active"][key] = {
            "username": username,
            "ip": ip_addr,
            "logon_type": logon_type,
            "attempts": attempts,
            "last_seen": str(event_time),
            "alert": alert,
        }
        _state["last_updated"] = _now_iso()


def run_detector(log_path="logs.json"):
    with _lock:
        _state["started_at"] = _now_iso()
        _state["last_updated"] = _now_iso()

    try:
        import win32evtlog
    except ImportError:
        with _lock:
            _state["status"] = "error"
            _state["message"] = (
                "pywin32 (win32evtlog) is not available. This detector must "
                "run on Windows with pywin32 installed (pip install pywin32) "
                "and access to the Security event log."
            )
        _write_logs_json(log_path)
        return

    failed_logins = defaultdict(list)
    last_record = 0

    try:
        handle = win32evtlog.OpenEventLog(None, "Security")
    except Exception as exc:
        with _lock:
            _state["status"] = "error"
            _state["message"] = (
                f"Could not open the Security event log: {exc}. "
                "Try running as Administrator."
            )
        _write_logs_json(log_path)
        return

    flags = (win32evtlog.EVENTLOG_FORWARDS_READ |
             win32evtlog.EVENTLOG_SEQUENTIAL_READ)

    with _lock:
        _state["status"] = "running"
        _state["message"] = "Monitoring failed logons (EventID 4625)..."
    _write_logs_json(log_path)

    try:
        while True:
            events_found = False

            while True:
                events = win32evtlog.ReadEventLog(handle, flags, last_record)

                if not events:
                    break

                events_found = True

                for event in events:
                    last_record = event.RecordNumber

                    if event.EventID != 4625:  # failed logon
                        continue

                    if not event.StringInserts:
                        continue

                    try:
                        username = event.StringInserts[5]
                        logon_type = event.StringInserts[10]
                        ip_addr = event.StringInserts[19]
                        event_time = event.TimeGenerated
                    except IndexError:
                        continue

                    key = (username, ip_addr)
                    failed_logins[key].append(event_time)
                    failed_logins[key] = [
                        t for t in failed_logins[key]
                        if event_time - t <= TIME_WINDOW
                    ]

                    attempts = len(failed_logins[key])
                    alert = attempts >= THRESHOLD

                    _record_event(username, ip_addr, logon_type,
                                   event_time, attempts, alert)
                    _write_logs_json(log_path)

            if not events_found:
                time.sleep(POLL_INTERVAL)

    except Exception as exc:
        with _lock:
            _state["status"] = "error"
            _state["message"] = f"Detector stopped unexpectedly: {exc}"
        _write_logs_json(log_path)

    finally:
        win32evtlog.CloseEventLog(handle)


def get_state():
    with _lock:
        return json.loads(json.dumps(_state, default=str))


def start_in_background(log_path="logs.json"):
    """Starts run_detector() in a daemon thread and returns immediately."""
    thread = threading.Thread(target=run_detector, args=(log_path,), daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    run_detector()
