import re
import ipaddress

RISKY_TLDS = [".ru", ".tk", ".xyz", ".top", ".click"]
SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "paypal", "bank", "alert"]


def detect_ioc_type(value):
    value = value.strip()

    try:
        ipaddress.ip_address(value)
        return "IP Address"
    except ValueError:
        pass

    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "MD5 Hash"

    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "SHA1 Hash"

    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "SHA256 Hash"

    if "." in value:
        return "Domain"

    return "Unknown"


def analyze_ioc(value):
    value = value.strip().lower()
    ioc_type = detect_ioc_type(value)

    score = 0
    notes = []

    if ioc_type == "IP Address":
        ip = ipaddress.ip_address(value)

        if ip.is_private:
            notes.append("Private/internal IP address detected")
            score += 5
        else:
            notes.append("Public IP address detected")
            score += 15

    elif ioc_type == "Domain":
        notes.append("Domain indicator detected")
        score += 10

        for tld in RISKY_TLDS:
            if value.endswith(tld):
                notes.append(f"Risky top-level domain detected: {tld}")
                score += 30

        for word in SUSPICIOUS_WORDS:
            if word in value:
                notes.append(f"Suspicious keyword found in domain: {word}")
                score += 10

    elif "Hash" in ioc_type:
        notes.append(f"{ioc_type} indicator detected")
        score += 20

    else:
        notes.append("IOC type could not be clearly identified")
        score += 5

    if score >= 60:
        risk = "High"
    elif score >= 30:
        risk = "Medium"
    else:
        risk = "Low"

    analyst_note = f"""
IOC analyzed: {value}

Type: {ioc_type}
Risk Level: {risk}
Risk Score: {score}

Suggested SOC actions:
- Check this indicator in threat intelligence sources
- Search for the indicator in SIEM logs
- Review related alerts and endpoint activity
- Escalate if the indicator appears in real traffic
"""

    return {
        "ioc": value,
        "type": ioc_type,
        "score": score,
        "risk": risk,
        "notes": notes,
        "analyst_note": analyst_note
    }