# Threat Intelligence Dashboard

A simple SOC-style cybersecurity project built with Python and Streamlit for analyzing Indicators of Compromise (IOCs).

## Features

* Detects IOC types (IP addresses, domains, and hashes)
* Assigns risk levels (Low, Medium, High)
* Calculates a basic threat score
* Provides detailed analysis for each IOC
* Interactive dashboard built with Streamlit

## Technologies

* Python
* Streamlit
* Pandas
* Regex

## Installation

```bash
git clone https://github.com/codescueduard24/threat-intelligence-dashboard.git
cd threat-intelligence-dashboard
pip install -r requirements.txt
```

## Run

```bash
streamlit run app.py
```

## Example IOCs

```text
8.8.8.8
192.168.1.10
paypal-security-alert.xyz
44d88612fea8a8f36de82e1278abb02f
```


