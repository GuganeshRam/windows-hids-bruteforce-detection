#### Windows Authentication Log Monitoring System (HIDS)

##### 

##### Overview



This project is a Python-based Host Intrusion Detection System (HIDS) designed to monitor Windows Security Event Logs and detect brute-force authentication attempts in real time. It focuses on identifying repeated failed login attempts using event correlation and threshold-based detection logic, simulating common SOC and Blue Team monitoring workflows.



##### Features



* Monitors Windows Security Event Logs for failed authentication attempts
* Detects Event ID 4625 (failed logon events)
* Tracks failed login attempts by username and source IP address
* Implements time-window based threshold detection
* Generates real-time alerts when suspicious activity is detected

##### 

##### Technologies Used



* Python
* Windows Event Log API (win32evtlog)
* Windows Security Logs



##### Detection Logic

* Event ID: 4625 (Failed Logon)
* Threshold: 5 failed attempts
* Time Window: 60 seconds
* Alert Condition: Triggered when failed attempts exceed the threshold within the defined time window for the same user and IP address



##### Project Structure



windows-hids-bruteforce-detection/

├── src/

&nbsp;   └── hids.py

├── README.md

├── requirements.txt

├── .gitignore



##### Installation and Setup



###### Prerequisites



* Windows Operating System
* Python 3.x
* Administrator privileges (required to access Security Event Logs)



###### Install Dependencies

pip install pywin32



###### Running the Project

python src/hids.py



###### Sample Output

\[failed login] user=admin ip=192.168.1.10 attempts=5

\[alert] brute-force detected user=admin ip=192.168.1.10



##### Use Cases



* Security Operations Center (SOC) monitoring simulation
* Blue Team and defensive security practice
* Windows authentication threat detection
* Log analysis and correlation exercises



##### Future Enhancements



* Export alerts to log files or SIEM-compatible formats
* Email or webhook-based alerting
* Support for additional Windows authentication-related event IDs
* Visualization and reporting integration
