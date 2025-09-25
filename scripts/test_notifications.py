#!/usr/bin/env python3
"""Test script for notifications"""

import os
import sys

# Add the project root to Python path
sys.path.insert(0, '/home/logntsu/siem_lab')

from mini_siem.notifications import notification_manager
from mini_siem.geoip import geoip_lookup


def test_geoip():
    """Test GeoIP lookup"""
    print("Testing GeoIP lookup...")
    
    test_ips = [
        "8.8.8.8",        # Google DNS
        "1.1.1.1",        # Cloudflare DNS
        "127.0.0.1",      # Localhost
        "192.168.1.1",    # Private IP
    ]
    
    for ip in test_ips:
        geo_info = geoip_lookup.lookup(ip)
        location = geoip_lookup.get_formatted_location(ip)
        threat_level = geoip_lookup.get_threat_level(ip)
        
        print(f"IP: {ip}")
        print(f"  Location: {location}")
        print(f"  Threat Level: {threat_level}")
        print(f"  Details: {geo_info}")
        print()


def test_notifications():
    """Test notification system"""
    print("Testing notifications...")
    
    # Test brute force notification
    test_ip = "203.0.113.1"
    test_usernames = ["root", "admin", "test"]
    
    geo_info = geoip_lookup.lookup(test_ip)
    
    print(f"Testing brute force notification for IP: {test_ip}")
    notification_manager.notify_brute_force_detected(
        ip=test_ip,
        attempts=5,
        usernames=test_usernames,
        geo_info=geo_info
    )
    
    print("Testing IP blocked notification...")
    notification_manager.notify_ip_blocked(
        ip=test_ip,
        reason="Test blocking",
        duration=3600,
        geo_info=geo_info
    )
    
    print("Testing system status notification...")
    notification_manager.notify_system_status(
        status="TESTING",
        details="This is a test notification from Mini SIEM"
    )


def main():
    print("Mini SIEM Notification Test")
    print("=" * 40)
    
    # Check environment variables
    print("Environment variables:")
    env_vars = [
        "SIEM_SMTP_SERVER", "SIEM_SMTP_USER", "SIEM_FROM_EMAIL",
        "SIEM_NOTIFICATION_EMAILS", "SIEM_SLACK_WEBHOOK", "IPSTACK_API_KEY"
    ]
    
    for var in env_vars:
        value = os.environ.get(var, "Not set")
        if "PASSWORD" in var or "KEY" in var or "WEBHOOK" in var:
            value = "***" if value != "Not set" else value
        print(f"  {var}: {value}")
    
    print("\n" + "=" * 40)
    
    try:
        test_geoip()
        test_notifications()
        print("All tests completed!")
    except Exception as e:
        print(f"Test failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
