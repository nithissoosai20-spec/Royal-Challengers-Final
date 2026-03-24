"""
Manual Test Script for AbuseIPDB Blocking Feature
Run this when staff/evaluator asks for demonstration
"""

from app import block_ip, get_ip_intel, send_alert_emails
import sys

print("="*60)
print("🎯 AbuseIPDB Blocking Feature - Manual Test")
print("="*60)

# Known malicious IPs (Tor exit nodes / known attackers)
test_ips = [
    "185.220.101.1",   # Tor exit node
    "185.220.101.2",   # Tor exit node
    "45.142.212.61",   # Known malicious
    "89.248.165.146",  # Known malicious
]

print("\n📋 Testing with known malicious IPs...\n")

for test_ip in test_ips:
    print(f"Testing IP: {test_ip}")
    print("-" * 40)
    
    # Get intelligence from AbuseIPDB
    intel = get_ip_intel(test_ip)
    
    print(f"  Location: {intel['city']}, {intel['country']}")
    print(f"  ISP: {intel['isp']}")
    print(f"  🚨 Abuse Score: {intel['abuse_score']}%")
    print(f"  📊 Total Reports: {intel['abuse_reports']}")
    
    # Check if it meets blocking threshold
    if intel['abuse_score'] >= 75:
        print(f"  ✅ BLOCKING: Score {intel['abuse_score']}% exceeds threshold (75%)")
        
        # Block the IP
        block_ip(test_ip, f"Manual Demo: High AbuseIPDB score {intel['abuse_score']}%")
        
        # Send alert emails
        send_alert_emails(
            "🚨 DEMO: Malicious IP Blocked",
            f"IP {test_ip} was blocked during demonstration.\n\n"
            f"Location: {intel['city']}, {intel['country']}\n"
            f"ISP: {intel['isp']}\n"
            f"Abuse Score: {intel['abuse_score']}%\n"
            f"Total Reports: {intel['abuse_reports']}\n\n"
            f"This IP has been automatically blocked by the system."
        )
        
        print(f"  📧 Alert emails sent to SOC team")
        print(f"  ✅ IP successfully blocked!\n")
        
        # Found one, stop here
        print("="*60)
        print("✅ DEMONSTRATION COMPLETE!")
        print("="*60)
        print("\n📌 Next Steps:")
        print("1. Login to your dashboard as Super Admin")
        print("2. Scroll down to '🚫 Blocked IPs' section")
        print("3. You'll see the blocked IP with all details")
        print("4. Check your email for the alert notification")
        print("\n💡 To unblock: Click 'Unblock' button in dashboard")
        sys.exit(0)
    else:
        print(f"  ⚠️ Score {intel['abuse_score']}% is below threshold (75%)")
        print(f"  ⏭️ Trying next IP...\n")

print("\n⚠️ None of the test IPs had high enough abuse scores.")
print("💡 Try visiting https://www.abuseipdb.com/categories and find a recent high-score IP")
