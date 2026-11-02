# Flask SOC Ticketing Application

## Overview

A Python Flask-based SOC incident management application that receives security alerts from Splunk, processes incident information, and automatically creates tickets for security events.

## Architecture

1. Suricata generates network security events.
2. Splunk collects and analyzes Suricata events.
3. Splunk sends alert data to the Flask webhook.
4. Flask processes incoming JSON alerts.
5. SQLite stores incident tickets.
6. The SOC dashboard displays and manages incidents.

## Features

- Automated ticket creation through Flask webhook.
- Splunk alert integration using JSON.
- SQLite database for ticket storage.
- Duplicate incident prevention using fingerprints.
- Incident severity classification.
- Source IP and destination IP tracking.
- Occurrence count and timestamps.
- Search and filter functionality.
- Ticket status management: Open, In Progress, Resolved.
- SOC incident dashboard.

## Technology Stack

- Python
- Flask
- SQLite
- Splunk Enterprise
- Suricata IDS
- JSON
- HTML, CSS, JavaScript

## Installation

Clone the repository:

```bash
git clone https://github.com/rahuldhankher03/Splunk-Suricata-SOC-Ticketing.git
cd Splunk-Suricata-SOC-Ticketing
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

Open:

`http://127.0.0.1:5000`

## Webhook Endpoint

**Method:** POST

**Endpoint:** `/webhook`

The webhook receives JSON security alerts from Splunk and processes them to generate SOC tickets.

## Database

SQLite automatically initializes `tickets.db` and stores:

- Ticket ID
- Incident title
- Source and destination IP
- Username
- Severity
- Status
- Occurrence count
- Created and last-seen timestamps

## SOC Workflow

Suricata Detection → Splunk SIEM → SPL Alert → Flask Webhook → SQLite Ticket → SOC Dashboard

## Disclaimer

Developed for cybersecurity learning, SOC lab practice, and educational demonstration purposes.
