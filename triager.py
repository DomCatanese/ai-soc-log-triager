import json
import ollama

LOG_FILE = "auth_sample.log"
MODEL = "llama3.2:3b"

def read_logs(filepath):
    with open(filepath, "r") as f:
        return f.read()

def run_triage(log_data):
    system_prompt = (
        "You are an automated Tier-2 SOC ingestion engine. "
        "Analyze raw server logs for malicious activity. "
        "Return ONLY a JSON array of detected threats. "
        "Each object must contain: 'attack_type', 'source_ip', 'severity' (Low/Medium/High/Critical), "
        "'evidence' (exact log line match), and 'recommended_action'. "
        "Ignore normal user logins and benign system events."
    )

    user_prompt = f"Analyze these logs and extract threats:\n\n{log_data}"

    print(f"[*] Triaging logs with {MODEL} (structured JSON output)...\n")
    
    response = ollama.chat(
        model=MODEL,
        format="json",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        options={"temperature": 0.0}
    )
    return response['message']['content']

def generate_firewall_rules(threats):
    rules = []
    blocked_ips = set()

    for threat in threats:
        ip = threat.get("source_ip")
        severity = threat.get("severity", "").lower()
        if ip and severity in ["high", "critical"] and ip not in blocked_ips:
            rules.append(f"netsh advfirewall firewall add rule name=\"Block_{ip}\" dir=in action=block remoteip={ip}")
            blocked_ips.add(ip)
            
    return rules

if __name__ == "__main__":
    logs = read_logs(LOG_FILE)
    raw_json = run_triage(logs)
    
    try:
        data = json.loads(raw_json)
        threats = data if isinstance(data, list) else data.get("threats", data.get("findings", [data]))
        
        print("=" * 65)
        print("             STRUCTURED INCIDENT REPORT (JSON)")
        print("=" * 65)
        print(json.dumps(threats, indent=2))
        
        print("\n" + "=" * 65)
        print("           AUTO-GENERATED MITIGATION COMMANDS")
        print("=" * 65)
        rules = generate_firewall_rules(threats)
        if rules:
            for rule in rules:
                print(f"[+] Suggested Rule: {rule}")
        else:
            print("[*] No high/critical severity threats requiring immediate blocking.")
            
    except json.JSONDecodeError:
        print("[!] Raw output was not valid JSON:")
        print(raw_json)