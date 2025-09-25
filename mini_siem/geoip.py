import json
import os
import time
from typing import Dict, Optional
from urllib.parse import urlencode

import requests

from .logger import logger


class GeoIPLookup:
    """Geolocation lookup for IP addresses"""
    
    def __init__(self):
        self.cache: Dict[str, Dict] = {}
        self.cache_duration = 3600  # 1 hour cache
        self.api_key = os.environ.get("IPSTACK_API_KEY")
        self.fallback_service = "http://ip-api.com/json/"
    
    def _is_cache_valid(self, ip: str) -> bool:
        """Check if cached data is still valid"""
        if ip not in self.cache:
            return False
        
        cached_time = self.cache[ip].get("_cached_at", 0)
        return time.time() - cached_time < self.cache_duration
    
    def _get_from_ipstack(self, ip: str) -> Optional[Dict]:
        """Get geolocation from ipstack.com (requires API key)"""
        if not self.api_key:
            return None
        
        try:
            url = f"http://api.ipstack.com/{ip}"
            params = {
                "access_key": self.api_key,
                "format": 1
            }
            
            response = requests.get(url, params=params, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            
            if "error" in data:
                logger.warning(f"IPStack API error: {data['error']}")
                return None
            
            return {
                "country": data.get("country_name", "Unknown"),
                "country_code": data.get("country_code", "XX"),
                "city": data.get("city", "Unknown"),
                "region": data.get("region_name", "Unknown"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "isp": data.get("connection", {}).get("isp", "Unknown"),
                "organization": data.get("connection", {}).get("organization", "Unknown"),
                "_cached_at": time.time(),
                "_source": "ipstack"
            }
            
        except Exception as e:
            logger.warning(f"IPStack lookup failed for {ip}: {e}")
            return None
    
    def _get_from_ipapi(self, ip: str) -> Optional[Dict]:
        """Get geolocation from ip-api.com (free service)"""
        try:
            # ip-api.com has rate limits, so we use batch lookup for multiple IPs
            url = self.fallback_service + ip
            
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get("status") != "success":
                logger.warning(f"ip-api.com lookup failed for {ip}: {data.get('message', 'Unknown error')}")
                return None
            
            return {
                "country": data.get("country", "Unknown"),
                "country_code": data.get("countryCode", "XX"),
                "city": data.get("city", "Unknown"),
                "region": data.get("regionName", "Unknown"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "isp": data.get("isp", "Unknown"),
                "organization": data.get("org", "Unknown"),
                "_cached_at": time.time(),
                "_source": "ipapi"
            }
            
        except Exception as e:
            logger.warning(f"ip-api.com lookup failed for {ip}: {e}")
            return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False
    
    def lookup(self, ip: str) -> Optional[Dict]:
        """Get geolocation information for an IP address"""
        # Skip lookup for private IPs
        if self._is_private_ip(ip):
            return {
                "country": "Private Network",
                "country_code": "XX",
                "city": "Local",
                "region": "Private",
                "latitude": None,
                "longitude": None,
                "isp": "Private",
                "organization": "Private Network",
                "_cached_at": time.time(),
                "_source": "private"
            }
        
        # Check cache first
        if self._is_cache_valid(ip):
            return self.cache[ip]
        
        # Try ipstack first (if API key available), then fallback to ip-api
        geo_data = self._get_from_ipstack(ip) or self._get_from_ipapi(ip)
        
        if geo_data:
            self.cache[ip] = geo_data
            logger.info(f"GeoIP lookup for {ip}: {geo_data['country']}, {geo_data['city']}")
        else:
            # Cache negative result to avoid repeated failed lookups
            self.cache[ip] = {
                "country": "Unknown",
                "country_code": "XX",
                "city": "Unknown",
                "region": "Unknown",
                "latitude": None,
                "longitude": None,
                "isp": "Unknown",
                "organization": "Unknown",
                "_cached_at": time.time(),
                "_source": "failed"
            }
        
        return self.cache[ip]
    
    def get_formatted_location(self, ip: str) -> str:
        """Get a formatted location string for an IP"""
        geo_data = self.lookup(ip)
        if not geo_data:
            return "Unknown Location"
        
        if geo_data["country"] == "Private Network":
            return "Private Network"
        
        location_parts = []
        if geo_data["city"] and geo_data["city"] != "Unknown":
            location_parts.append(geo_data["city"])
        if geo_data["country"] and geo_data["country"] != "Unknown":
            location_parts.append(geo_data["country"])
        
        return ", ".join(location_parts) if location_parts else "Unknown Location"
    
    def get_threat_level(self, ip: str) -> str:
        """Determine threat level based on geolocation"""
        geo_data = self.lookup(ip)
        if not geo_data:
            return "unknown"
        
        if geo_data["country"] == "Private Network":
            return "low"
        
        # Simple threat assessment based on country
        high_risk_countries = ["CN", "RU", "KP", "IR"]  # Add more as needed
        medium_risk_countries = ["BR", "IN", "ID", "TH"]  # Add more as needed
        
        country_code = geo_data.get("country_code", "").upper()
        
        if country_code in high_risk_countries:
            return "high"
        elif country_code in medium_risk_countries:
            return "medium"
        else:
            return "low"
    
    def clear_cache(self):
        """Clear the geolocation cache"""
        self.cache.clear()
        logger.info("GeoIP cache cleared")


# Global GeoIP lookup instance
geoip_lookup = GeoIPLookup()
