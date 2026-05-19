from __future__ import annotations

from models.pfsense import BlockRequest, BlockResponse
from typing import List, Dict

async def get_firewall_rules() -> List[Dict]:
    """
    Fetch the current firewall rules from the pfSense API.
    Implementation will query the pfSense API endpoint for firewall rules
    and return a list of dictionaries representing each rule.
    """
    raise NotImplementedError("pfSense API not configured yet")

async def block_ip(ip: str, reason: str, analysis_id: str) -> Dict:
    """
    Block a specific IP address in the pfSense firewall.
    Implementation will send a request to the pfSense API to add a block rule
    for the given IP address, including the reason and analysis ID for tracking.
    """
    raise NotImplementedError("pfSense API not configured yet")

async def block_ip_list(ips: List[str], reason: str, analysis_id: str) -> List[Dict]:
    """
    Block a list of IP addresses in the pfSense firewall.
    Implementation will iterate over the list of IPs and call the pfSense API
    to add block rules for each IP address, including the reason and analysis ID.
    """
    raise NotImplementedError("pfSense API not configured yet")

async def unblock_ip(ip: str) -> Dict:
    """
    Unblock a specific IP address in the pfSense firewall.
    Implementation will send a request to the pfSense API to remove the block rule
    for the given IP address.
    """
    raise NotImplementedError("pfSense API not configured yet")

async def get_blocked_ips() -> List[Dict]:
    """
    Fetch the list of currently blocked IP addresses from the pfSense firewall.
    Implementation will query the pfSense API endpoint for blocked IPs
    and return a list of dictionaries representing each blocked IP.
    """
    raise NotImplementedError("pfSense API not configured yet")

async def create_alias(name: str, ips: List[str], description: str) -> Dict:
    """
    Create an alias in the pfSense firewall for a group of IP addresses.
    Implementation will send a request to the pfSense API to create an alias
    with the given name, list of IPs, and description.
    """
    raise NotImplementedError("pfSense API not configured yet")
