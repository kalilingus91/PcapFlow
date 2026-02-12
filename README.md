# PcapFlow Analyzer 

A simple web tool to analyze network traffic (.pcap) files.

## Features
- **Charts:** Visual protocol distribution (TCP, UDP, etc.).
- **Security:** Detects potential threats and suspicious activity.
- **Passwords:** Extracts cleartext credentials from traffic.
- **History:** Keeps a log of all past analyses.

## Tech Stack
- **Backend:** Python, Django, Scapy.
- **Frontend:** Bootstrap, Chart.js.

## How to Run
1. **Clone:** `git clone https://github.com/kalilingus91/PcapFlow.git`
2. **Install:** `pip install -r requirements.txt`
3. **Database:** `python manage.py migrate`
4. **Start:** `python manage.py runserver`

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.
