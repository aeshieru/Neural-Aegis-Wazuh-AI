#!/var/ossec/framework/python/bin/python3
import sys
import json
import requests
import datetime
import signal
from google import genai

# --- CONFIGURATION ---
WEBHOOK_URL = "DISCORD_WEBHOOK_HERE"
GEMINI_API_KEY = "GEMINI_API_KEY_HERE"
LOG_FILE = "/var/ossec/logs/active-responses.log"

SEVERITY_BRAIN = {
    "wevtutil": 11, "procdump": 10, "sekurlsa": 12, "mimikatz": 12,
    "reg save": 9, "net user /add": 9, "invoke-atomic": 8
}
# ---------------------

def log_debug(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')} active-response/gemini: {msg}\n")
    except: pass

def timeout_handler(signum, frame):
    raise TimeoutError("Script execution exceeded time limit.")

signal.signal(signal.SIGALRM, timeout_handler)
signal.alarm(45)

def send_discord(level, agent_data, rule_desc, mitre_id, analysis_text, original_level):
    name = agent_data.get('name', 'Unknown')
    ip = agent_data.get('ip', 'N/A')
    mitre_link = f"https://attack.mitre.org/techniques/{mitre_id}/" if mitre_id else None

    if level >= 11: status, color = "🔴 CRITICAL", 15548997
    elif level >= 7: status, color = "🟠 HIGH", 15105570
    elif level >= 4: status, color = "🟡 MEDIUM", 16776960
    else: status, color = "🔵 INFO", 3447003

    embed = {
        "title": f"{status}: {rule_desc}",
        "description": analysis_text[:2000],
        "url": mitre_link,
        "color": color,
        "fields": [
            {"name": "🖥️ Target Machine", "value": f"**Name:** `{name}`\n**IP:** `{ip}`", "inline": True},
            {"name": "📊 Metrics", "value": f"**Current Level:** `{level}`\n**Wazuh Level:** `{original_level}`", "inline": True},
            {"name": "🔗 MITRE ID", "value": f"[{mitre_id}]({mitre_link})" if mitre_id else "N/A", "inline": False}
        ],
        "footer": {"text": "Neural Aegis AI Engine"},
        "timestamp": datetime.datetime.utcnow().isoformat()
    }
    requests.post(WEBHOOK_URL, json={"embeds": [embed]}, timeout=10)

# --- SMART INPUT HANDLER ---
try:
    log_debug("--- Script Started ---")
    alert_json = None

    # Scenario A: Integration (Alert file path in argv[1])
    if len(sys.argv) > 1:
        log_debug(f"Integration Mode: Opening {sys.argv[1]}")
        with open(sys.argv[1]) as f:
            alert_json = json.load(f)

    # Scenario B: Active Response (JSON stream in STDIN)
    else:
        log_debug("Active Response Mode: Reading STDIN...")
        stdin_data = sys.stdin.read().strip()
        if stdin_data:
            raw_data = json.loads(stdin_data)
            alert_json = raw_data.get('parameters', {}).get('alert', raw_data)
        else:
            raise ValueError("No data found in STDIN or Arguments")

    # 2. EXTRACT DATA
    description = alert_json.get('rule', {}).get('description', 'Unknown Rule')
    agent_info = alert_json.get('agent', {})
    wazuh_level = int(alert_json.get('rule', {}).get('level', 0))
    full_log = str(alert_json.get('full_log', '')).lower()
    mitre_ids = alert_json.get('rule', {}).get('mitre', {}).get('id', [])
    mitre_id = mitre_ids[0] if mitre_ids else None

    # 3. SEVERITY OVERRIDE
    display_level = wazuh_level
    for keyword, boost in SEVERITY_BRAIN.items():
        if keyword in full_log:
            display_level = max(display_level, boost)

    # 4. AI ANALYSIS
    log_debug(f"Querying Gemini for Level {display_level}...")
    client = genai.Client(api_key=GEMINI_API_KEY)
    prompt = f"Analyze this SOC alert. Level: {display_level}. Rule: {description}. Log: {json.dumps(alert_json)}"

    response = client.models.generate_content(model="gemini-2.5-flash-lite", contents=prompt)
    ai_text = response.text.replace("```markdown", "").replace("```", "")

    # 5. SEND
    send_discord(display_level, agent_info, description, mitre_id, ai_text, wazuh_level)
    log_debug("--- Script Finished Successfully ---")

except Exception as e:
    log_debug(f"CRITICAL ERROR: {str(e)}")