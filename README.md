\# 🤖 AI-SOC Alert Analyzer



\### Wazuh Security Monitoring + Gemini AI Investigation



AI-powered Security Operations Center (SOC) alert analysis platform that combines \*\*Wazuh\*\*, \*\*FastAPI\*\*, and \*\*Google Gemini AI\*\* to monitor security alerts, investigate suspicious events, assess risk, and provide actionable recommendations for SOC analysts.



\---



\## 📌 Project Overview



\*\*AI-SOC Alert Analyzer\*\* is a practical SOC monitoring and investigation project designed to reduce the time required to analyze security alerts.



The system collects real security alerts from \*\*Wazuh\*\*, sends them to a \*\*FastAPI backend\*\*, and uses \*\*Google Gemini AI\*\* to analyze the alert and generate an analyst-friendly investigation report.



The dashboard provides security metrics, alert details, AI-generated investigation results, risk scores, and recommended next steps.



\---



\## 🏗️ Architecture



```text

┌──────────────────────┐

│   Windows Endpoint   │

│   Security Events    │

└──────────┬───────────┘

&#x20;          │

&#x20;          ▼

┌──────────────────────┐

│     Wazuh Agent      │

└──────────┬───────────┘

&#x20;          │

&#x20;          ▼

┌──────────────────────┐

│    Wazuh Manager     │

│ Alert Detection      │

│ Rules + Decoders     │

└──────────┬───────────┘

&#x20;          │

&#x20;          ▼

┌──────────────────────┐

│ Custom AI-SOC        │

│ Integration          │

└──────────┬───────────┘

&#x20;          │

&#x20;          ▼

┌──────────────────────┐

│   Cloudflare Tunnel  │

│ Secure Webhook Route │

└──────────┬───────────┘

&#x20;          │

&#x20;          ▼

┌──────────────────────┐

│    FastAPI Backend   │

│ Alert API + Webhook  │

└──────────┬───────────┘

&#x20;          │

&#x20;          ▼

┌──────────────────────┐

│    Google Gemini AI  │

│ Alert Investigation  │

└──────────┬───────────┘

&#x20;          │

&#x20;          ▼

┌──────────────────────┐

│    SOC Dashboard     │

│ Risk + Evidence +    │

│ Investigation        │

└──────────────────────┘

```



\---



\## 🔄 End-to-End Workflow



1\. A security event occurs on the Windows endpoint.

2\. The Wazuh Agent collects the event.

3\. Wazuh Manager analyzes the event using its rules and decoders.

4\. A security alert is generated.

5\. The custom `custom-ai-soc` integration forwards the alert.

6\. Cloudflare Tunnel securely exposes the local FastAPI webhook.

7\. FastAPI receives and stores the Wazuh alert.

8\. The analyst selects an alert from the dashboard.

9\. Gemini AI analyzes the selected alert.

10\. The dashboard displays the investigation result.

11\. The analyst validates the AI findings and performs the required response.



\---



\## ✨ Key Features



\### 🛡️ Real Wazuh Monitoring



\* Real-time Wazuh alert ingestion

\* Windows endpoint monitoring

\* Wazuh rule and decoder integration

\* Security event collection

\* Alert severity classification



\### 🤖 Gemini AI Investigation



\* AI-powered alert analysis

\* Suspicious activity explanation

\* Evidence extraction

\* Risk scoring

\* Investigation recommendations

\* Recommended remediation

\* Analyst validation guidance



\### 📊 SOC Dashboard



\* Total alert count

\* Low / Medium / High / Critical statistics

\* Alert listing

\* Alert severity visibility

\* Agent information

\* Rule information

\* Detailed alert investigation

\* Gemini AI analysis panel



\### 🔎 Security Investigation



The AI analysis provides:



\* Verdict

\* Risk score

\* What happened

\* Why the event may be suspicious

\* Evidence

\* MITRE ATT\&CK mapping when reliable

\* Recommended fix

\* Next investigation steps

\* Final analyst-oriented verdict



\---



\## 🧪 Real Wazuh + Gemini Test



The project was tested using a real Windows event that was successfully detected by Wazuh.



\### Test Event



```text

Rule ID: 60602

Rule Level: 9

Event ID: 1000

Channel: Application

Severity: ERROR

```



The event was received by Wazuh, forwarded through the custom integration, processed by FastAPI, and made available for Gemini AI investigation.



\### Example AI Result



```text

Verdict: Needs Investigation

Risk Score: 60/100

Risk Level: HIGH

```



The AI identified the event as potentially requiring investigation while also recognizing that the available evidence suggested it could be an authorized test event.



The system recommended validating the event and checking related process activity before taking containment actions.



\---



\## 🧰 Technology Stack



| Technology              | Purpose                             |

| ----------------------- | ----------------------------------- |

| Wazuh                   | SIEM / security monitoring          |

| Wazuh Agent             | Endpoint telemetry collection       |

| FastAPI                 | Backend API and webhook             |

| Python                  | Backend and integration development |

| Google Gemini           | AI-powered alert investigation      |

| Cloudflare Tunnel       | Secure webhook connectivity         |

| HTML / CSS / JavaScript | SOC dashboard                       |

| Windows 11              | Monitored endpoint                  |

| Ubuntu                  | Wazuh server                        |

| AWS EC2                 | Wazuh server hosting                |

| Git / GitHub            | Version control and project hosting |



\---



\## 📁 Project Structure



```text

AI-SOC-Alert-Analyzer/

│

├── backend/

│   ├── main.py

│   ├── main.py.backup

│   └── main\_backup.py

│

├── frontend/

│   ├── index.html

│   └── index\_backup.html

│

├── data/

│   ├── sample\_alerts.json

│   └── wazuh\_alerts.jsonl

│

├── .gitignore

├── README.md

└── requirements.txt

```



> Backup files are retained for development reference.



\---



\## ⚙️ Requirements



Before running the project, install:



\* Python 3.10+

\* FastAPI

\* Uvicorn

\* Google Gemini SDK

\* python-dotenv

\* Wazuh Manager

\* Wazuh Agent

\* Cloudflare Tunnel



\---



\## 🚀 Installation



\### 1. Clone the Repository



```bash

git clone https://github.com/hackthensh/AI-SOC-Alert-Analyzer.git

cd AI-SOC-Alert-Analyzer

```



\### 2. Install Python Dependencies



```bash

pip install -r requirements.txt

```



If `requirements.txt` is not present in an older checkout:



```bash

pip install fastapi uvicorn aiofiles google-genai python-dotenv

```



\---



\## 🔐 Environment Variables



Create a `.env` file:



```env

GEMINI\_API\_KEY=your\_gemini\_api\_key

```



Never commit the `.env` file to GitHub.



The project uses `.gitignore` to exclude sensitive environment files.



\---



\## ▶️ Run the FastAPI Backend



From the project root:



```bash

python -m uvicorn backend.main:app --reload

```



The backend will normally be available at:



```text

http://127.0.0.1:8000

```



\---



\## 🌐 Cloudflare Tunnel



To expose the local FastAPI server for Wazuh webhook communication:



```bash

cloudflared tunnel --url http://127.0.0.1:8000

```



Cloudflare generates a temporary public HTTPS URL.



Configure the Wazuh integration to send alerts to:



```text

https://YOUR-CLOUDFLARE-URL/api/wazuh-webhook

```



> Quick Tunnel URLs are temporary and should not be permanently documented as production endpoints.



\---



\## 🔗 Wazuh Integration



The project uses a custom Wazuh integration:



```text

/var/ossec/integrations/custom-ai-soc

```



The integration forwards Wazuh JSON alerts to the FastAPI webhook.



Example Wazuh configuration:



```xml

<integration>

&#x20;   <name>custom-ai-soc</name>

&#x20;   <hook\_url>https://YOUR-CLOUDFLARE-URL/api/wazuh-webhook</hook\_url>

&#x20;   <alert\_format>json</alert\_format>

</integration>

```



After configuration, restart the Wazuh Manager:



```bash

sudo systemctl restart wazuh-manager

```



\---



\## 🔌 API Endpoints



\### Health Check



```text

GET /health

```



Checks whether the backend is running.



\### Wazuh Webhook



```text

POST /api/wazuh-webhook

```



Receives Wazuh alerts.



\### Wazuh Alerts



```text

GET /api/wazuh-alerts

```



Returns collected Wazuh alerts.



\### Wazuh Summary



```text

GET /api/wazuh-summary

```



Returns alert statistics and severity information.



\---



\## 🧠 AI Investigation Flow



When an analyst selects an alert:



```text

Wazuh Alert

&#x20;    ↓

Alert Evidence Extraction

&#x20;    ↓

Gemini AI

&#x20;    ↓

Security Analysis

&#x20;    ↓

Risk Assessment

&#x20;    ↓

MITRE ATT\&CK Mapping

&#x20;    ↓

Recommended Fix

&#x20;    ↓

Next Investigation

&#x20;    ↓

SOC Analyst Validation

```



\---



\## 📊 Dashboard



The SOC dashboard displays:



\* Backend status

\* Total alerts

\* Low severity alerts

\* Medium severity alerts

\* High severity alerts

\* Critical alerts

\* Wazuh alert details

\* Rule ID

\* Rule level

\* Agent information

\* Source information

\* Gemini investigation results



\### Dashboard Screenshots



Add your project screenshots here:



```text

docs/screenshots/dashboard.png

docs/screenshots/gemini-analysis.png

```



Example:



```markdown

!\[SOC Dashboard](docs/screenshots/dashboard.png)



!\[Gemini Investigation](docs/screenshots/gemini-analysis.png)

```



\---



\## 🧑‍💻 SOC Use Cases



This project demonstrates practical SOC workflows such as:



\### 1. Security Alert Monitoring



Monitor security events collected from endpoints.



\### 2. Alert Triage



Prioritize alerts based on severity and risk.



\### 3. AI-Assisted Investigation



Use Gemini AI to summarize and investigate security alerts.



\### 4. Evidence Analysis



Extract important fields such as:



\* Timestamp

\* Agent ID

\* Hostname

\* IP address

\* Rule ID

\* Rule level

\* Event ID

\* Provider

\* Process information

\* Security event details



\### 5. MITRE ATT\&CK Mapping



Map suspicious behavior to relevant MITRE ATT\&CK techniques when sufficient evidence exists.



\### 6. Incident Investigation



Provide recommended next steps for SOC analysts.



\### 7. Analyst Validation



AI recommendations are treated as analyst assistance rather than automatic incident-response decisions.



\---



\## 🔒 Security Considerations



\### Secrets



Never commit:



```text

.env

API keys

Passwords

Access tokens

Private credentials

```



\### AI Security



Gemini AI output should be treated as \*\*analyst assistance\*\*, not absolute truth.



Security analysts should validate:



\* Alert evidence

\* Endpoint activity

\* Process execution

\* Related events

\* Network activity

\* User activity



before performing containment or remediation.



\---



\## ☁️ Deployment Architecture



A practical deployment can use:



```text

AWS EC2

&#x20;  │

&#x20;  └── Wazuh Manager

&#x20;         │

&#x20;         ▼

&#x20;    Wazuh Alerts

&#x20;         │

&#x20;         ▼

&#x20; Custom Integration

&#x20;         │

&#x20;         ▼

&#x20;  FastAPI Backend

&#x20;         │

&#x20;         ▼

&#x20;     Gemini AI

&#x20;         │

&#x20;         ▼

&#x20;   SOC Dashboard

```



The development environment can use Cloudflare Tunnel to connect the Wazuh server to the local FastAPI application.



\---



\## 🔮 Future Improvements



Planned enhancements include:



\* Automated incident response

\* SOAR integration

\* Email / Slack notifications

\* Threat intelligence enrichment

\* IOC extraction

\* VirusTotal integration

\* MITRE ATT\&CK visualization

\* User authentication

\* Role-based access control

\* PostgreSQL database

\* Docker deployment

\* Kubernetes deployment

\* AWS-native deployment

\* Alert correlation

\* Detection engineering

\* AI-assisted incident reports

\* PDF investigation reports



\---



\## 🎯 Skills Demonstrated



This project demonstrates practical knowledge of:



\* SOC Operations

\* SIEM

\* Wazuh

\* Security Monitoring

\* Alert Triage

\* Incident Investigation

\* Windows Event Analysis

\* Linux Administration

\* FastAPI

\* Python

\* REST APIs

\* Webhooks

\* Google Gemini AI

\* Cloudflare Tunnel

\* AWS EC2

\* MITRE ATT\&CK

\* Git

\* GitHub

\* Security Automation

\* AI-assisted Cybersecurity



\---



\## 🏆 Project Outcome



The project demonstrates an end-to-end security monitoring and AI-assisted investigation workflow:



```text

Real Security Event

&#x20;       ↓

Windows Endpoint

&#x20;       ↓

Wazuh Agent

&#x20;       ↓

Wazuh Manager

&#x20;       ↓

Custom Integration

&#x20;       ↓

FastAPI Webhook

&#x20;       ↓

Gemini AI

&#x20;       ↓

Risk Assessment

&#x20;       ↓

SOC Analyst Dashboard

```



This demonstrates how AI can assist SOC analysts with \*\*alert triage, investigation, evidence analysis, and prioritization\*\* while keeping the human analyst responsible for final decisions.



\---



\## ⚠️ Disclaimer



This project is intended for:



\* Educational purposes

\* Cybersecurity learning

\* SOC analyst practice

\* Security monitoring demonstrations

\* Authorized lab environments



Do not use this project to monitor systems or networks without proper authorization.



\---



\## 👨‍💻 Author



\*\*AI-SOC Alert Analyzer\*\*



Cybersecurity / SOC Portfolio Project



GitHub:



```text

https://github.com/hackthensh/AI-SOC-Alert-Analyzer

```



\---



\## ⭐ Support



If you find this project useful, consider giving the repository a ⭐ on GitHub.



\---



\### 🔐 Security Monitoring + AI Investigation



\*\*Detect → Analyze → Investigate → Validate → Respond\*\*



