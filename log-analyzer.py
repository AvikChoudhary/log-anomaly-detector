import re
from collections import Counter

def analyze_log(log_file):
    suspicious = []
    failed_logins = 0
    ip_attempts = Counter()
    
    with open(log_file, 'r') as f:
        for line in f:
            if re.search(r'failed|invalid|denied', line, re.IGNORECASE):
                failed_logins += 1
                suspicious.append(f"Suspicious: {line.strip()}")
            
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
            if ip_match:
                ip = ip_match.group()
                ip_attempts[ip] += 1
                if ip_attempts[ip] > 5:
                    suspicious.append(f"Possible brute-force from {ip}")
    
    return failed_logins, ip_attempts, suspicious

def main():
    print("=== Log Anomaly Detector (Simple IDS Prototype) ===\n")
    log_file = "sample_log.txt"
    failed, ips, alerts = analyze_log(log_file)
    
    print(f"Total failed login attempts detected: {failed}")
    print("\nTop IP addresses by activity:")
    for ip, count in ips.most_common(5):
        print(f"  {ip}: {count} attempts")
    
    print("\n=== ALERTS ===")
    for alert in alerts[:10]:
        print(alert)

if __name__ == "__main__":
    main()
