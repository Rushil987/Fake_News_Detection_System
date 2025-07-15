from config.settings import WHOISXML_API_KEY
import requests
from urllib.parse import urlparse
from datetime import datetime, timezone
import tldextract

SUSPICIOUS_EXTENSIONS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".icu", ".pw", ".buzz",
    ".site", ".online", ".work", ".click", ".info", ".loan", ".shop", ".best",
    ".rest", ".fun", ".party", ".review", ".stream", ".host", ".website",
    ".press", ".download", ".cam", ".date", ".trade", ".vip", ".life", ".win",
    ".biz", ".pro", ".club", ".ooo", ".world"
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "gmx.com", "yandex.com", "mail.com", "zoho.com",
    "tutanota.com", "icloud.com", "rediffmail.com", "inbox.lv", "hushmail.com",
    "mail.ru", "rambler.ru", "qq.com", "yopmail.com", "temp-mail.org",
    "guerrillamail.com", "10minutemail.com", "mailinator.com", "sharklasers.com",
    "throwawaymail.com"
}

SUSPICIOUS_KEYWORDS = {
    "login", "secure", "update", "verify", "bank", "account", "signin", "payment",
    "invoice", "ebay", "paypal", "dropbox", "webscr", "admin", "support", "service",
    "billing", "confirm", "security", "limited", "alert", "important", "authenticate",
    "password", "token", "unlock", "recover", "upgrade", "verifyidentity", "access",
    "checkout", "bonus", "free", "prize", "claim", "gift", "reward", "survey",
    "urgent", "suspend", "apple", "amazon", "wallet", "cryptowallet", "bitcoins",
    "coinbase", "exchange", "webmail", "office365", "windows", "microsoft", "android"
}

SUSPICIOUS_DNS_PROVIDERS = {
    "freenom", "000webhost", "infinitefree", "awardspace", "biz.nf", "byet.org", "heliohost",
    "epizy.com", "profreehost", "freehostia.com", "webhostapp.com", "hostinger", "weeblydns.net",
    "godaddysites.com", "googledomains.com", "cloudns.net", "runhosting.com", "inmotionhosting.com",
    "host-ed.net", "bravenet.com", "freehosting.com", "freehostingnoads.net", "my3gb.com", "server155.com",
    "000a.biz", "ns1.afraid.org", "ns2.afraid.org", "hostslb.com", "suspended-domain.com",
    "dnsowl.com", "porkbun.com", "dynadot.com", "buddyns.com", "changeip.com", "no-ip.com", "duckdns.org",
    "dynu.com", "ddns.net", "dyndns.org", "tzo.com", "xh0st.com", "ns1.parklogic.com", "ns2.parklogic.com",
    "ns1.abovedomains.com", "ns2.abovedomains.com", "parked.com", "ns1.voodoo.com",
    "ns2.voodoo.com", "ns1.bodis.com", "ns2.bodis.com", "hostwindsdns.com", "inmotionhosting.com",
    "ns1.namecheaphosting.com", "ns2.namecheaphosting.com", "ns1.hostmonster.com", "ns2.hostmonster.com",
    "ns1.justhost.com", "ns2.justhost.com", "ns1.bluehost.com", "ns2.bluehost.com", "ns1.siteground.net",
    "ns2.siteground.net", "ns1.dreamhost.com", "ns2.dreamhost.com", "ns3.dreamhost.com"
}

def check_redirection(url):
    """Check if the URL redirects and return the final destination"""
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        final_url = response.url
        if get_domain(final_url) != get_domain(url):
            return final_url
        return None
    except requests.exceptions.RequestException as e:
        return f"Error: {e}"

def get_domain(url):
    """Extract domain name from a URL"""
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()

def get_whoisxml_data(domain, api_key=WHOISXML_API_KEY):
    """Fetch WHOIS information of a domain using WHOISXML API"""
    api_url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
    params = {
        "apiKey": api_key,
        "domainName": domain,
        "outputFormat": "JSON"
    }
    
    try:
        response = requests.get(api_url, params=params)
        response.raise_for_status()
        data = response.json()
        whois_data = data.get("WhoisRecord", {})
        return {
            "Domain Name": whois_data.get("domainName"),
            "Domain Status": whois_data.get("status", []),
            "Registrar": whois_data.get("registrarName"),
            "Creation Date": whois_data.get("createdDate"),
            "Expiration Date": whois_data.get("expiresDate"),
            "Updated Date": whois_data.get("updatedDate"),
            "Name Servers": whois_data.get("nameServers", {}).get("hostNames", []),
            "Emails": whois_data.get("contactEmail"),
            "Registrant Name": whois_data.get("registrant", {}).get("name"),
            "Registrant Org": whois_data.get("registrant", {}).get("organization"),
            "Registrant Country": whois_data.get("registrant", {}).get("country"),
            "Registrant Email": whois_data.get("registrant", {}).get("email"),
            "Admin Email": whois_data.get("administrativeContact", {}).get("email"),
            "Tech Email": whois_data.get("technicalContact", {}).get("email"),
            "DNSSEC": whois_data.get("dnssec")
        }
    except Exception as e:
        return f"Error fetching WHOISXML data: {e}"

def analyze_subdomain(url):
    """Analyze the subdomain part of a URL for suspicious patterns."""
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain.lower()
    warnings = []
    risk_score = 0
    
    if subdomain:
        # Check for suspicious keywords
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in subdomain:
                risk_score += 2
                warnings.append(f"Subdomain contains suspicious keyword '{keyword}'.")
                break
        
        # Check complexity
        if len(subdomain.split('.')) > 2:
            risk_score += 2
            warnings.append("Subdomain is overly complex.")
        
        # Check hyphens
        if subdomain.count('-') > 2:
            risk_score += 1
            warnings.append("Subdomain contains many hyphens.")
    
    return risk_score, warnings

def analyze_whois_data(domain, whois_data):
    """Analyze WHOISXML API data to assess phishing risk"""
    risk_score = 0
    warnings = []
    
    if not isinstance(whois_data, dict):
        return 0, ["Could not retrieve WHOIS data"]
    
    # Parse ISO datetime strings
    def parse_date(date_str):
        try:
            return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except Exception:
            return None
    
    
    creation_date = parse_date(whois_data.get("Creation Date")) if whois_data.get("Creation Date") else None
    expiration_date = parse_date(whois_data.get("Expiration Date")) if whois_data.get("Expiration Date") else None
    now = datetime.now(timezone.utc)
    
    if creation_date:
        domain_age = (now - creation_date).days
        if domain_age < 180:  # Less than 6 months
            risk_score += 3
            warnings.append("Domain is newly registered (<6 months).")
    else:
        risk_score += 2
        warnings.append("Creation date not available.")
    
    
    if expiration_date:
        if (expiration_date - now).days < 365:
            risk_score += 3
            warnings.append("Domain expires in <1 year.")
    else:
        risk_score += 2
        warnings.append("Expiration date not available.")
    
    
    domain_status = whois_data.get("Domain Status", "")
    if domain_status and "hold" in domain_status.lower():
        risk_score += 3
        warnings.append("Domain status indicates hold/suspension.")
    
    
    registrant_email = whois_data.get("Registrant Email")
    if registrant_email:
        email_domain = registrant_email.split("@")[-1].lower()
        if email_domain in FREE_EMAIL_DOMAINS:
            risk_score += 2
            warnings.append("Registrant email is from free provider.")
    else:
        risk_score += 2
        warnings.append("Registrant email missing.")
    
    
    name_servers = whois_data.get("Name Servers", [])
    if not name_servers:
        risk_score += 2
        warnings.append("No name servers listed.")
    else:
        for ns in name_servers:
            if any(provider in ns.lower() for provider in SUSPICIOUS_DNS_PROVIDERS):
                risk_score += 2
                warnings.append(f"Suspicious DNS provider: {ns}")
                break
    
    
    dnssec = whois_data.get("DNSSEC")
    if not dnssec or dnssec.lower() != "signeddelegation":
        risk_score += 1
        warnings.append("DNSSEC not properly enabled.")
    
    
    for ext in SUSPICIOUS_EXTENSIONS:
        if domain.endswith(ext):
            risk_score += 3
            warnings.append(f"Suspicious domain extension: {ext}")
            break
    
    return risk_score, warnings

def analyze_url_parts(url):
    """Analyze URL components for suspicious indicators"""
    parsed = urlparse(url)
    risk_score = 0
    warnings = []
    
    
    if parsed.scheme != "https":
        risk_score += 1
        warnings.append("URL not using HTTPS")
    
    
    if parsed.port and ((parsed.scheme == "https" and parsed.port != 443) or 
                       (parsed.scheme == "http" and parsed.port != 80)):
        risk_score += 1
        warnings.append(f"Non-standard port: {parsed.port}")
    
    
    path = parsed.path.lower()
    query = parsed.query.lower()
    
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in path:
            risk_score += 1
            warnings.append(f"Path contains '{keyword}'")
        if keyword in query:
            risk_score += 1
            warnings.append(f"Query contains '{keyword}'")
    
    if len(query) > 100:
        risk_score += 1
        warnings.append("Long query string")
    
    return risk_score, warnings

def detect_phishing(original_url):
    """Main phishing detection function"""
    API_KEY = WHOISXML_API_KEY  # Set in config/settings.py
    original_domain = get_domain(original_url)
    
    
    whois_data = get_whoisxml_data(original_domain, API_KEY)
    
    
    whois_score, whois_warnings = analyze_whois_data(original_domain, whois_data)
    sub_score, sub_warnings = analyze_subdomain(original_url)
    url_parts_score, url_parts_warnings = analyze_url_parts(original_url)
    
    
    total_risk = whois_score + sub_score + url_parts_score
    all_warnings = whois_warnings + sub_warnings + url_parts_warnings
    
    
    if final_url := check_redirection(original_url):
        if get_domain(final_url) != original_domain:
            total_risk += 4
            all_warnings.append("Suspicious redirection detected")
    
    
    score = min(100, round(total_risk / 45 * 100))
    
    return {
        'risk_score': score,
        'warnings': all_warnings,
        'domain': original_domain
    }


if __name__ == "__main__":
    url = input("\nEnter URL: ")
    result = detect_phishing(url)
    print(f"\nRisk Score: {result['risk_score']}%")
    print("Warnings:")
    for warning in result['warnings']:
        print(f"- {warning}")