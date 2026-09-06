import re

def extract_indicators(text: str) -> dict:
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|info|biz|xyz|top|online|site|tk|ml|ga|cf|gq|win|club|live|shop|app|dev)\b'
    email_pattern = r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'

    urls     = list(set(re.findall(url_pattern, text)))
    ips      = list(set(re.findall(ip_pattern, text)))
    emails   = list(set(re.findall(email_pattern, text)))

    # Extract domains from URLs and standalone
    raw_domains = re.findall(domain_pattern, text)
    url_domains = [re.sub(r'https?://', '', u).split('/')[0] for u in urls]
    email_domains = [e.split('@')[1] for e in emails]
    domains  = list(set(raw_domains + url_domains + email_domains))

    # Remove IPs that matched as domains
    domains  = [d for d in domains if not re.match(ip_pattern, d)]

    # Private IPs (not useful for threat intel)
    public_ips = [ip for ip in ips if not (
        ip.startswith('10.') or ip.startswith('192.168.') or
        ip.startswith('172.') or ip == '127.0.0.1'
    )]

    return {
        "ips": public_ips,
        "domains": domains[:10],  # cap at 10 to avoid API abuse
        "urls": urls[:10],
        "emails": emails,
        "private_ips": [ip for ip in ips if ip not in public_ips]
    }