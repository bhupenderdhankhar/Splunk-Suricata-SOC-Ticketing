# Splunk SIEM + Suricata IDS
### Real-Time Threat Detection & Automated SOC Ticketing

![Splunk](https://img.shields.io/badge/SIEM-Splunk-000000?logo=splunk)
![Suricata](https://img.shields.io/badge/IDS-Suricata-EF3B2D)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python)
![Flask](https://img.shields.io/badge/Backend-Flask-000000?logo=flask)
![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite)
![Linux](https://img.shields.io/badge/OS-Ubuntu-E95420?logo=ubuntu)

## Project Overview

Developed a hands-on SOC monitoring and incident management solution by integrating **Suricata IDS with Splunk Enterprise** and a custom **Python Flask ticketing application**.

The solution collects and analyzes network security events, identifies suspicious activity, generates automated alerts, and creates incident tickets through a webhook integration.

It demonstrates a practical security monitoring and incident management workflow.

## Key Features

| Feature | Description |
|---|---|
| SIEM Integration | Centralized Suricata event monitoring in Splunk |
| Network Threat Detection | Analysis of Suricata EVE JSON events |
| SPL Detection Queries | Searches for suspicious network activity |
| Automated Alerting | Splunk alert configuration |
| Webhook Integration | Sends alert data to Flask |
| Automated Ticket Creation | Creates incident tickets from security alerts |
| Duplicate Prevention | Prevents duplicate ticket creation for matching incidents |
| Incident Management | Open, In Progress and Resolved statuses |
| SOC Dashboard | Ticket statistics, search, filtering and incident tracking |

## Architecture

```mermaid
flowchart TD
    A[Kali Linux / Network Activity] --> B[Network Traffic]
    B --> C[Suricata IDS]
    C --> D[EVE JSON Logs]
    D --> E[Splunk Enterprise]
    E --> F[SPL Detection Queries]
    F --> G[Configured Splunk Alert]
    G --> H[Webhook]
    H --> I[Python Flask Application]
    I --> J[Duplicate Prevention]
    J --> K[SQLite Database]
    K --> L[SOC Command Center Dashboard]
    L --> M[Incident Investigation and Status Updates]
```

## Technology Stack

- **SIEM:** Splunk Enterprise
- **IDS:** Suricata
- **Programming:** Python
- **Backend:** Flask
- **Database:** SQLite
- **Query Language:** Splunk Processing Language (SPL)
- **Operating System:** Ubuntu Linux
- **Testing Environment:** Kali Linux
- **Integration:** HTTP Webhook / JSON
- **Virtualization:** VMware

## Project Screenshots

### 1. SOC Command Center Dashboard

Overview of security incidents, ticket counts, severity levels, and incident statuses.

![SOC Command Center](screenshots/soc-command-center-dashboard.png)

### 2. Splunk Suricata Event Monitoring

Suricata EVE JSON events searched and analyzed using Splunk SPL.

![Splunk Suricata Search](screenshots/splunk-suricata-alert-search.png)

### 3. Splunk Alert and Webhook Configuration

Configured Splunk alert actions to send event data to the Flask webhook endpoint.

![Splunk Webhook Configuration](screenshots/splunk-alert-webhook-configuration.png)

### 4. Flask Ticketing Server

Flask application running and receiving webhook requests.

![Flask Server](screenshots/flask-ticketing-webhook-server.png)

### 5. Webhook Ticket Creation Test

Tested webhook integration using a JSON payload and verified successful ticket creation.

![Webhook Ticket Creation](screenshots/webhook-ticket-creation-test.png)

### 6. Security Incident Details

Incident details including severity, source IP, occurrence count, timestamps, and original event payload.

![Incident Details](screenshots/soc-incident-ticket-details.png)

## Incident Management Workflow

1. Suricata monitors network traffic and generates security events.
2. Events are written to EVE JSON logs.
3. Splunk collects and indexes the events.
4. SPL searches identify relevant security activity.
5. Configured Splunk alerts trigger when their conditions are met.
6. Webhook sends alert data to the Flask application.
7. Flask processes the payload and checks for duplicates.
8. New incidents are stored in SQLite.
9. SOC dashboard displays tickets for investigation and tracking.

## Ticketing Application Features

- Automated ticket creation through webhook.
- Unique SOC ticket ID generation.
- Severity and incident information.
- Source and destination IP tracking when provided.
- Occurrence count and event timestamps.
- Duplicate alert prevention.
- Incident status management.
- Search and filtering.
- Dashboard summary cards.

## Example Incident

| Field | Example |
|---|---|
| Incident | Possible SSH Brute Force Attack |
| Ticket ID | SOC-58320509 |
| Severity | High |
| Source IP | 192.168.113.131 |
| Occurrences | 23 |
| Status | Open |

*Example values from the lab demonstration.*

## Repository Documentation

- [Implementation Guide](documentation/implementation-guide.md)
- [Splunk Detection Queries](splunk/detection-queries.md)
- [Ticketing Application](ticketing-app/README.md)
- [Testing and Validation](testing/test-cases.md)

## Skills Demonstrated

- SIEM monitoring and log analysis
- Network security event investigation
- Splunk SPL queries
- IDS and SIEM integration
- Alert configuration and webhook integration
- Python Flask application development
- Incident creation and tracking
- Basic SOC incident management workflow

## About the Developer

**Bhupender Dhankhar**

B.Tech – Computer Science & Engineering (Cyber Security)  
Gurugram University

Aspiring SOC Analyst | SIEM | Network Security | Threat Detection | Incident Response

[LinkedIn Profile](https://www.linkedin.com/in/bhupender-dhankhar-41299a351)

## Disclaimer

This project was developed for educational purposes in an authorized virtual lab. All testing was conducted on systems under my control or with permission.
