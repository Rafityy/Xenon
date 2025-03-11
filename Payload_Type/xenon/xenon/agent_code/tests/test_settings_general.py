#!/usr/bin/python3
import struct

# Configuration dictionary
Config = {
    "payload_uuid": "589144d4-bf3e-4774-bac8-6304e699e3ed",
    "callback_domains": ["https://mythic.c2.com:443", "https://10.2.20.248:443", "https://example.com:443" ],
    "domain_rotation": "random",
    "callback_interval": 1,
    "callback_jitter": 0,
    "killdate": "",
    "failover_threshold": 7,
    "encryption": True,
    "aes_key": "rj5ttLLnOHVIvFP6/IuRuRIMKw68sTqDOSA8LmbzbDQ=",
    "proxyEnabled": False,
    "proxy_host": "",
    "proxy_user": "",
    "proxy_pass": "",
}

# Helper functions for serialization
def serialize_string(string, pack_size=True):
    """Serialize a string with an optional size prefix."""
    data = b""
    if pack_size:
        data += len(string).to_bytes(4, "big")
    data += string.encode()
    
    return data

def serialize_int(data):
    """Serialize an integer as a 4-byte big-endian value."""
    return data.to_bytes(4, "big")

def serialize_bool(data):
    """Serialize a boolean as a byte."""
    x = 1 if data else 0
    return x.to_bytes(1, "big")

# Start serialization
serialized_data = b""

# Serialize the payload UUID
serialized_data += serialize_string(Config["payload_uuid"], pack_size=False)

# Serialize encryption settings
serialized_data += serialize_bool(Config["encryption"])
if Config["encryption"]:
    serialized_data += serialize_string(Config["aes_key"])

# Serialize proxy settings
serialized_data += serialize_bool(Config["proxyEnabled"])
if Config["proxyEnabled"]:
    serialized_data += serialize_string(Config["proxy_host"])
    serialized_data += serialize_string(Config["proxy_user"])
    serialized_data += serialize_string(Config["proxy_pass"])

# Serialize sleep time and jitter
serialized_data += serialize_int(Config["callback_interval"])  # Sleep time
serialized_data += serialize_int(Config["callback_jitter"])    # Jitter

# Serialize domain rotation and failover threshold
rotation_strategies = {
    "round-robin": 0,
    "fail-over": 1,
    "random": 2
}
strategy = Config.get("domain_rotation", "fail-over")
domain_rotation_value = rotation_strategies.get(strategy)
serialized_data += serialize_int(domain_rotation_value)
serialized_data += serialize_int(Config["failover_threshold"])


# Serialize number of hosts (callback domains)
num_hosts = len(Config["callback_domains"])
serialized_data += serialize_int(num_hosts)

# Serialize each callback domain
for url in Config["callback_domains"]:
    # Parse the URL to get hostname, port, and SSL flag
    if url.startswith("https://"):
        ssl = True
        url_without_scheme = url[len("https://"):]
    elif url.startswith("http://"):
        ssl = False
        url_without_scheme = url[len("http://"):]
    else:
        raise ValueError("Invalid URL scheme")

    # Split hostname and port
    hostname, port = url_without_scheme.split(':')
    port = int(port)

    print(f"Hostname: {hostname}, Port: {port}, SSL: {ssl}")
    # Serialize hostname, port, and SSL flag
    serialized_data += serialize_string(hostname)
    serialized_data += serialize_int(port)
    serialized_data += serialize_bool(ssl)

# Convert to hex string format for C macro
hex_string = ''.join(f'\\x{byte:02X}' for byte in serialized_data)

# Output as C macro
print(f'#define S_AGENT_CONFIG "{hex_string}"')
