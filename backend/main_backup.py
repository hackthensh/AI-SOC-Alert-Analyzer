from pathlib import Path
import json
import os
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from google import genai


# ============================================================
# PATHS & ENVIRONMENT
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
FRONTEND_DIR = BASE_DIR / "frontend"

DATA_DIR.mkdir(parents=True, exist_ok=True)

ALERT_FILE = DATA_DIR / "alerts.json"
WAZUH_ALERT_FILE = DATA_DIR / "wazuh_alerts.jsonl"

load_dotenv(BASE_DIR / ".env")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY:
    gemini_client = genai.Client(api_key=GEMINI_API_KEY)
else:
    gemini_client = None


# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="AI-SOC Alert Analyzer",
    version="1.0.0",
    description="AI-powered SOC alert analysis using Wazuh and Google Gemini.",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# FRONTEND
# ============================================================

if FRONTEND_DIR.exists():
    app.mount(
        "/dashboard",
        StaticFiles(directory=str(FRONTEND_DIR), html=True),
        name="dashboard",
    )


# ============================================================
# MODELS
# ============================================================

class AlertRequest(BaseModel):
    alert: Dict[str, Any]


# ============================================================
# GENERIC JSON HELPERS
# ============================================================

def load_json_file(file_path: Path) -> Any:
    if not file_path.exists():
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return []


def load_alerts() -> List[Dict[str, Any]]:
    data = load_json_file(ALERT_FILE)

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        return [data]

    return []


# ============================================================
# WAZUH JSONL LOADER
# ============================================================

def load_wazuh_alerts() -> List[Dict[str, Any]]:
    """
    Wazuh alerts.json is JSON Lines:
    one JSON object per line.
    """

    if not WAZUH_ALERT_FILE.exists():
        return []

    alerts = []

    try:
        with open(
            WAZUH_ALERT_FILE,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as file:

            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    alert = json.loads(line)

                    if isinstance(alert, dict):
                        alerts.append(alert)

                except json.JSONDecodeError:
                    continue

    except Exception:
        return []

    return alerts


# ============================================================
# REAL WINDOWS WAZUH ALERTS
# ============================================================

def get_real_windows_alerts() -> List[Dict[str, Any]]:
    alerts = load_wazuh_alerts()

    windows_alerts = []

    for alert in alerts:

        agent = alert.get("agent", {})

        if not isinstance(agent, dict):
            continue

        agent_id = str(agent.get("id", ""))

        # Windows agent
        if agent_id != "001":
            continue

        rule = alert.get("rule", {})

        if not isinstance(rule, dict):
            rule = {}

        rule_id = str(rule.get("id", ""))

        # Ignore artificial test rule if present
        if rule_id == "9999":
            continue

        windows_alerts.append(alert)

    return windows_alerts


# ============================================================
# LATEST WINDOWS ALERT
# ============================================================

def get_latest_windows_wazuh_alert() -> Optional[Dict[str, Any]]:
    alerts = get_real_windows_alerts()

    if not alerts:
        return None

    return alerts[-1]


# ============================================================
# HIGHEST SEVERITY WINDOWS ALERT
# ============================================================

def get_highest_severity_windows_alert() -> Optional[Dict[str, Any]]:
    alerts = get_real_windows_alerts()

    if not alerts:
        return None

    def severity(alert: Dict[str, Any]) -> int:
        try:
            rule = alert.get("rule", {})

            if not isinstance(rule, dict):
                return 0

            return int(rule.get("level", 0) or 0)

        except Exception:
            return 0

    highest = max(
        alerts,
        key=lambda alert: (
            severity(alert),
            str(alert.get("timestamp", "")),
        ),
    )

    return highest


def get_latest_wazuh_alert() -> Optional[Dict[str, Any]]:
    return get_latest_windows_wazuh_alert()


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(alert_level: int) -> int:

    if alert_level >= 12:
        return 90

    if alert_level >= 10:
        return 75

    if alert_level >= 7:
        return 60

    if alert_level >= 4:
        return 40

    if alert_level >= 1:
        return 20

    return 0


# ============================================================
# MITRE EXTRACTION
# ============================================================

def extract_mitre(alert: Dict[str, Any]) -> Dict[str, Any]:

    rule = alert.get("rule", {})

    if not isinstance(rule, dict):
        rule = {}

    mitre = rule.get("mitre", {})

    if not isinstance(mitre, dict):
        return {
            "ids": [],
            "tactics": [],
            "techniques": [],
        }

    ids = mitre.get("id", [])
    tactics = mitre.get("tactic", [])
    techniques = mitre.get("technique", [])

    if isinstance(ids, str):
        ids = [ids]

    if isinstance(tactics, str):
        tactics = [tactics]

    if isinstance(techniques, str):
        techniques = [techniques]

    return {
        "ids": ids,
        "tactics": tactics,
        "techniques": techniques,
    }


# ============================================================
# ALERT DETAILS
# ============================================================

def extract_alert_details(alert: Dict[str, Any]) -> Dict[str, Any]:

    rule = alert.get("rule", {})

    if not isinstance(rule, dict):
        rule = {}

    agent = alert.get("agent", {})

    if not isinstance(agent, dict):
        agent = {}

    mitre = extract_mitre(alert)

    try:
        alert_level = int(rule.get("level", 0) or 0)
    except Exception:
        alert_level = 0

    return {
        "rule_id": rule.get("id"),
        "alert_level": alert_level,
        "description": rule.get(
            "description",
            "No description available.",
        ),
        "agent": agent.get("name"),
        "agent_id": agent.get("id"),
        "agent_ip": agent.get("ip"),
        "risk_score": calculate_risk_score(alert_level),
        "mitre_ids": mitre["ids"],
        "mitre_tactics": mitre["tactics"],
        "mitre_techniques": mitre["techniques"],
        "timestamp": alert.get("timestamp"),
        "raw_alert": alert,
    }


# ============================================================
# GEMINI AI ANALYSIS
# ============================================================

def analyze_with_gemini(alert: Dict[str, Any]) -> Dict[str, Any]:

    if not GEMINI_API_KEY or gemini_client is None:
        return {
            "status": "error",
            "message": "GEMINI_API_KEY is not configured.",
        }

    prompt = f"""
You are an experienced SOC Analyst.

Analyze the following Wazuh security alert.

Provide a concise but useful SOC investigation.

Include:

1. Alert Summary
2. Severity Assessment
3. Risk
4. Possible Impact
5. Indicators / Important Details
6. MITRE ATT&CK Mapping if reasonably applicable
7. Investigation Steps
8. Recommended Response
9. Final SOC Analyst Verdict

Important:
- Do not invent facts.
- Clearly distinguish facts from assumptions.
- If the alert appears benign, explain why.
- If there is not enough information, say so.

WAZUH ALERT:

{json.dumps(alert, indent=2, default=str)}
"""

    try:

        response = gemini_client.models.generate_content(
            model="gemini-3.5-flash-lite",
            contents=prompt,
        )

        analysis = getattr(response, "text", None)

        if not analysis:
            analysis = str(response)

        return {
            "status": "success",
            "model": "gemini-3.5-flash-lite",
            "analysis": analysis,
        }

    except Exception as exc:

        error_message = str(exc)

        # Friendly handling for Gemini quota errors
        if "429" in error_message or "RESOURCE_EXHAUSTED" in error_message:

            return {
                "status": "error",
                "error_type": "quota_exceeded",
                "message": (
                    "Gemini API quota is currently exhausted. "
                    "The Wazuh alert pipeline is still working. "
                    "Try again after the quota resets or use a project "
                    "with available Gemini API quota."
                ),
                "details": error_message,
            }

        return {
            "status": "error",
            "error_type": "gemini_error",
            "message": error_message,
        }


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "project": "AI-SOC Alert Analyzer",
        "status": "online",
        "dashboard": "/dashboard",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "wazuh_alert_file": WAZUH_ALERT_FILE.exists(),
        "gemini_configured": bool(GEMINI_API_KEY),
    }


# ============================================================
# LOCAL ALERT API
# ============================================================

@app.get("/api/alerts")
def api_alerts():

    alerts = load_alerts()

    return {
        "status": "success",
        "count": len(alerts),
        "alerts": alerts,
    }


# ============================================================
# ALL WAZUH ALERTS
# ============================================================

@app.get("/api/wazuh-alerts")
def api_wazuh_alerts():

    alerts = load_wazuh_alerts()

    return {
        "status": "success",
        "source": "Wazuh",
        "count": len(alerts),
        "alerts": alerts,
    }


# ============================================================
# LATEST WAZUH ALERT
# ============================================================

@app.get("/api/wazuh-latest")
def api_wazuh_latest():

    alert = get_latest_wazuh_alert()

    if not alert:

        return {
            "status": "error",
            "message": "No real Windows Wazuh alerts found.",
        }

    return {
        "status": "success",
        "source": "Real Wazuh",
        **extract_alert_details(alert),
    }


# ============================================================
# LATEST WINDOWS WAZUH ALERT
# ============================================================

@app.get("/api/windows-wazuh-latest")
def api_windows_wazuh_latest():

    alert = get_latest_windows_wazuh_alert()

    if not alert:

        return {
            "status": "error",
            "message": "No Windows Wazuh alerts found.",
        }

    return {
        "status": "success",
        "source": "Real Wazuh Windows Agent",
        **extract_alert_details(alert),
    }


# ============================================================
# HIGHEST WINDOWS ALERT
# ============================================================

@app.get("/api/windows-wazuh-highest")
def api_windows_wazuh_highest():

    alert = get_highest_severity_windows_alert()

    if not alert:

        return {
            "status": "error",
            "message": "No Windows Wazuh alerts found.",
        }

    return {
        "status": "success",
        "source": "Real Wazuh Windows Agent",
        **extract_alert_details(alert),
    }


# ============================================================
# LOCAL ALERT ANALYSIS
# ============================================================

@app.post("/api/analyze")
def api_analyze(request: AlertRequest):

    return {
        "status": "success",
        "analysis": analyze_with_gemini(request.alert),
    }


# ============================================================
# ANALYZE LATEST LOCAL ALERT
# ============================================================

@app.get("/api/analyze-latest")
def api_analyze_latest():

    alerts = load_alerts()

    if not alerts:

        return {
            "status": "error",
            "message": "No local alerts available.",
        }

    alert = alerts[-1]

    return {
        "status": "success",
        "alert": alert,
        "ai_analysis": analyze_with_gemini(alert),
    }


# ============================================================
# AI ANALYSIS API
# ============================================================

@app.post("/api/ai-analyze")
def api_ai_analyze(request: AlertRequest):

    return {
        "status": "success",
        "alert": request.alert,
        "ai_analysis": analyze_with_gemini(request.alert),
    }


# ============================================================
# AI ANALYSIS OF LATEST REAL WAZUH ALERT
# ============================================================

@app.get("/api/ai-analyze-wazuh-latest")
def api_ai_analyze_wazuh_latest():

    alert = get_latest_wazuh_alert()

    if not alert:

        return {
            "status": "error",
            "message": "No real Windows Wazuh alert found.",
        }

    details = extract_alert_details(alert)

    ai_analysis = analyze_with_gemini(alert)

    return {
        "status": "success",
        "source": "Real Wazuh",
        **details,
        "ai_analysis": ai_analysis,
    }


# ============================================================
# WAZUH WEBHOOK
# ============================================================

@app.post("/api/wazuh-webhook")
def wazuh_webhook(alert: Dict[str, Any]):

    try:

        # Store each incoming Wazuh alert as one JSON line
        with open(
            WAZUH_ALERT_FILE,
            "a",
            encoding="utf-8",
        ) as file:

            file.write(
                json.dumps(
                    alert,
                    ensure_ascii=False,
                    default=str,
                )
                + "\n"
            )

        return {
            "status": "received",
            "source": "Wazuh",
            "saved": True,
        }

    except Exception as exc:

        return {
            "status": "error",
            "source": "Wazuh",
            "saved": False,
            "message": str(exc),
        }
