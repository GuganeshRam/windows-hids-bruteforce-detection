import time
import win32evtlog
from collections import defaultdict
from datetime import timedelta

time_window = timedelta(seconds=60)

failed_logins = defaultdict(list)
last_record = 0

handle = win32evtlog.OpenEventLog(None , "Security")  #log_type = "Security"

flags = (win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ)

print("[info] windows hids started. monitoring failed logins...")

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

                if event.EventID != 4625:  #failed_logonEventID = 4625
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
                    if event_time - t <= time_window
                ]

                attempts = len(failed_logins[key])

                print(
                    f"[failed login] "
                    f"user={username} ip={ip_addr} logon_type={logon_type} "
                    f"time={event_time} attempts={attempts}"
                )

                if attempts >= 5:  #threshold = 5
                    print(
                        f"[alert] brute-force detected "
                        f"user={username} ip={ip_addr} logon_type={logon_type} "
                    )

        if not events_found:
            time.sleep(5)  #sleep_interval = 5

except KeyboardInterrupt:
    print("\n[info]ids stopped by user")

finally:
    win32evtlog.CloseEventLog(handle)

