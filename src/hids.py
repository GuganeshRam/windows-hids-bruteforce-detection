import time
import win32evtlog
from collections import defaultdict
from datetime import timedelta


log_type = "Security"
failed_event_id = 4625
threshold = 5
time_window = timedelta(seconds=60)
sleep_interval = 5


failed_logins = defaultdict(list)
last_record = 0


handle = win32evtlog.OpenEventLog(None, log_type)

flags = (
    win32evtlog.EVENTLOG_FORWARDS_READ |
    win32evtlog.EVENTLOG_SEQUENTIAL_READ
)

print("[*] windows hids started. monitoring failed logins...")

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

                if event.EventID != failed_event_id:
                    continue

                if not event.StringInserts:
                    continue

                try:
                    username = event.StringInserts[1]
                    logon_type = event.StringInserts[5]
                    ip_addr = event.StringInserts[6]
                    event_time = event.TimeGenerated
                except IndexError:
                    continue

                key = (username, ip_addr)

                # store timestamp
                failed_logins[key].append(event_time)


                failed_logins[key] = [
                    t for t in failed_logins[key]
                    if event_time - t <= time_window
                ]

                attempts = len(failed_logins[key])

                print(
                    f"[failed login] "
                    f"user={username} ip={ip_addr} "
                    f"time={event_time} attempts={attempts}"
                )

                if attempts >= threshold:
                    print(
                        f"[alert] brute-force detected "
                        f"user={username} ip={ip_addr}"
                    )

        if not events_found:
            time.sleep(sleep_interval)

except KeyboardInterrupt:
    print("\n[*] ids stopped by user")

finally:
    win32evtlog.CloseEventLog(handle)

