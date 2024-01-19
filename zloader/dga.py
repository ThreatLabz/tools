import time
from datetime import datetime, timedelta

def uint32(val):
    return val & 0xffffffff

def get_dga_time():
    now = datetime.now()
    ts = time.time()
    utc_offset = (datetime.fromtimestamp(ts) - datetime.utcfromtimestamp(ts)).total_seconds() / 3600
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    midnight = midnight + timedelta(hours=utc_offset)
    return int(midnight.timestamp())

def generate_zloader_dga_domains():
    domains = []
    t = get_dga_time()
    for i in range(32): # number of domains to generate
        domain = ""
        for j in range(20): # domain name length
            v = uint32(ord('a') + (t % 25 ))
            t = uint32(t + v)
            t = (t >> 24) & ((t >> 24) ^ 0xFFFFFF00) | uint32(t << 8)
            domain += chr(v)
        domains.append(domain+".com")
    return domains

