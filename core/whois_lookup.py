import whois

def get_whois(target):
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

        # fixed: creation_date can be a list — always take first value
        cd = w.creation_date
        result["creation_date"] = str(cd[0] if isinstance(cd, list) else cd)

        ed = w.expiration_date
        result["expiration_date"] = str(ed[0] if isinstance(ed, list) else ed)

        result["name_servers"] = list(w.name_servers) if w.name_servers else []
        result["country"] = w.country
        result["org"] = w.org
        result["emails"] = list(w.emails) if w.emails else []

    except Exception as e:
        result["error"] = str(e)

    return result
