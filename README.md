🛡️ Neural Aegis: AI-Driven SOC Enrichment Framework
Neural Aegis is a high-fidelity security automation engine that bridges the gap between raw SIEM detections and actionable incident response. By integrating Wazuh (SIEM/XDR) with Google Gemini 2.5 Flash, it transforms cryptic logs into clinical SOC analyses in real-time.

![Attack Simulation](assets/demogif.gif)
🧭 Project Philosophy: Forensic Curiosity & The "How"
In modern cybersecurity, there is a comfortable trend toward becoming a "Dashboard Operator." It is easy to click a button and trust a vendor's "black box" logic to tell us if we are safe.

Neural Aegis was born out of a simple, persistent question: "How does the data actually get there?" Instead of just being a consumer, I wanted to experience the engineering "friction" involved in building a real-time response pipeline. I built this because I wanted to move past the summarized interface and understand the exact moment a raw Windows event is transformed into actionable intelligence.

🏗️ Technical Architecture
Endpoint: Windows 10/11 with Wazuh Agent & Sysmon.

Manager: Wazuh Server (Ubuntu) hosting the custom Python integration.

AI Engine: Google Gemini 2.5 Flash API for low-latency, high-context log interpretation.

Output: Discord Webhook with structured embeds and MITRE ATT&CK mapping.

✨ Key Features
Heuristic Severity Brain: Custom Python logic that intercepts logs and "boosts" severity based on high-risk technical markers (e.g., wevtutil, procdump, mimikatz).

Contextual Triage: Gemini 2.5 analyzes the raw JSON to provide:

Threat Actor Intent: Why is this happening?

Risk Level: Clinical assessment beyond the standard rule score.

Remediation: The exact command (PowerShell/CMD) to stop the threat.

MITRE ATT&CK Mapping: Automatic generation of clickable reference links for every detected technique.

Operational Resilience: Implemented signal.alarm timeout handlers and error handling for API rate limits (429 RESOURCE_EXHAUSTED).

🧠 The Learning Journey: Solving the "STDIN" Mystery
One of the most valuable parts of this project was overcoming technical roadblocks that managed services hide from you.

The Challenge: Initially, the script failed with a CRITICAL ERROR: Empty input from STDIN when triggered by the Wazuh Manager, despite working perfectly in a manual shell.

The Discovery: I discovered a fundamental difference in how Wazuh streams data:

Integrations pass data via a temporary file path in sys.argv[1].

Active Responses pass a raw JSON stream directly through STDIN.

The Solution: I engineered a Hybrid Input Handler that automatically detects the input source, ensuring the script is resilient whether triggered as a global integration or a specific active response.

🧪 Testing with Atomic Red Team
To validate the pipeline, I executed several MITRE-mapped simulations:

T1070.001 (Log Clearing): Detected via wevtutil and boosted to Level 11.

T1078.003 (Persistence): Detected unauthorized admin creation and boosted to Level 12.

🚀 Installation & Setup
Deployment: Place custom-gemini.py in /var/ossec/integrations/.

Permissions:

Bash

sudo chown root:wazuh /var/ossec/integrations/custom-gemini
sudo chmod 750 /var/ossec/integrations/custom-gemini
Configuration: Add the <integration> block to your ossec.conf and restart the Wazuh Manager.
(  <integration>
    <name>custom-gemini</name>
    <level>5</level>
    <hook_url>WEBHOOK URL HERE</hook_url>
    <alert_format>json</alert_format>
  </integration>
)
📈 Future Roadmap
VirusTotal Integration: Automated hash and IP reputation lookups.

Ollama Support: Integration with local LLMs (Llama 3) for air-gapped privacy.

Automated Host Isolation: AI-triggered active response for high-confidence threats.
