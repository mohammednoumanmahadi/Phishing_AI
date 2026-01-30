import socket
import whois

def get_whois(target):
    """
    Perform WHOIS lookup for domain or IP
    Returns dict safe for GUI / LLM usage
    """

    result = {
        "query": target,
        "domain_name": None,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": [],
        "country": None,
        "org": None,
        "emails": [],
        "error": None
    }

    try:
        w = whois.whois(target)

        result["domain_name"] = str(w.domain_name)
        result["registrar"] = w.registrar
        result["creation_date"] = str(w.creation_date)
        result["expiration_date"] = str(w.expiration_date)
        result["name_servers"] = list(w.name_servers) if w.name_servers else []
        result["country"] = w.country
        result["org"] = w.org
        result["emails"] = list(w.emails) if w.emails else []

    except Exception as e:
        result["error"] = str(e)

    return result
