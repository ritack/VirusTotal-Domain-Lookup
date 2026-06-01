import requests
from datetime import datetime, timezone

# Prompt the user for their VirusTotal API key.
api_key = input("Enter your VirusTotal API key: ")

# Headers required for VirusTotal API requests.
headers = {
    "accept": "application/json",
    "x-apikey": api_key
}


def format_timestamp(timestamp, fallback="Not Found"):
    """
    Convert a Unix timestamp into a readable UTC date/time string.

    If the timestamp is missing or empty, return the fallback value.
    """
    if not timestamp:
        return fallback

    return datetime.fromtimestamp(
        timestamp,
        tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")


def dns_records_by_type(dns_records, record_type, fallback="Not Found"):
    """
    Extract DNS record values of a specific type from the DNS records list.

    Example record types include A, MX, and NS.
    If no matching records are found, return the fallback value.
    """
    records = [
        item.get("value")
        for item in dns_records
        if item.get("type") == record_type and item.get("value")
    ]

    if not records:
        return fallback

    return ", ".join(records)


def get_relationship(domain, relationship, limit=5):
    """
    Retrieve related VirusTotal objects for a domain.

    The relationship parameter controls what type of related data is requested,
    such as subdomains or historical resolutions.
    """
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/{relationship}"

    # Limit the number of returned relationship records.
    params = {
        "limit": limit
    }

    response = requests.get(url, headers=headers, params=params)
    data = response.json()

    # Return an empty list if the API request fails or no data is returned.
    if response.status_code != 200 or "data" not in data:
        return []

    return data["data"]


def get_subdomains(domain, limit=5):
    """
    Retrieve a list of subdomains associated with the given domain.
    """
    items = get_relationship(domain, "subdomains", limit)

    # Each returned subdomain is stored in the item's id field.
    subdomains = [
        item.get("id")
        for item in items
        if item.get("id")
    ]

    return subdomains


def get_resolutions(domain, limit=5):
    """
    Retrieve historical DNS resolutions for the given domain.

    Each resolution includes the resolved IP address and the date it was observed.
    """
    items = get_relationship(domain, "resolutions", limit)

    resolutions = []

    for item in items:
        attributes = item.get("attributes", {})

        # Extract the resolved IP address and convert the resolution date.
        ip_address = attributes.get("ip_address", "Not Found")
        date = format_timestamp(attributes.get("date"))

        resolutions.append(f"{ip_address} ({date})")

    return resolutions


while True:
    # Ask the user for a domain until they choose to quit.
    domain = input("Enter a domain to lookup or Q to quit: ").strip()

    if domain.upper() == "Q":
        break

    # Request the main VirusTotal domain report.
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    response = requests.get(url, headers=headers)
    data = response.json()

    # Display the API error response if VirusTotal does not return domain data.
    if "data" not in data:
        print("VirusTotal error:")
        print(response.status_code)
        print(data)
        print()
        continue

    # VirusTotal stores most domain details inside the attributes object.
    attributes = data["data"]["attributes"]

    # Retrieve the most recent DNS records reported by VirusTotal.
    dns_records = attributes.get("last_dns_records", [])

    # Extract common DNS record types.
    a_records = dns_records_by_type(dns_records, "A")
    mx_records = dns_records_by_type(dns_records, "MX", "no mx")
    name_servers = dns_records_by_type(dns_records, "NS")

    # Convert the domain creation timestamp into a readable date.
    date_created = format_timestamp(attributes.get("creation_date"))

    # Extract detection statistics from VirusTotal vendors.
    analysis_stats = attributes.get("last_analysis_stats", {})
    malicious_count = analysis_stats.get("malicious", 0)
    suspicious_count = analysis_stats.get("suspicious", 0)

    # Extract domain registration and reputation information.
    registrar = attributes.get("registrar", "Not Found")
    reputation = attributes.get("reputation", "Not Found")

    # Extract and deduplicate category labels assigned by VirusTotal vendors.
    categories = attributes.get("categories", {})
    if categories:
        category_values = sorted(set(categories.values()))
        categories_display = ", ".join(category_values)
    else:
        categories_display = "Not Found"

    # Extract HTTPS certificate information if available.
    ssl_certificate = attributes.get("last_https_certificate", {})

    # Format the SSL certificate issuer fields for display.
    issuer = ssl_certificate.get("issuer", {})
    if issuer:
        issuer_display = ", ".join(
            f"{key}={value}" for key, value in issuer.items()
        )
    else:
        issuer_display = "Not Found"

    # Extract SSL certificate validity dates.
    validity = ssl_certificate.get("validity", {})
    cert_not_before = validity.get("not_before", "Not Found")
    cert_not_after = validity.get("not_after", "Not Found")

    # Retrieve and format related subdomains.
    subdomains = get_subdomains(domain, limit=5)
    if subdomains:
        subdomains_display = ", ".join(subdomains)
    else:
        subdomains_display = "Not Found"

    # Retrieve and format historical IP resolutions.
    resolutions = get_resolutions(domain, limit=5)
    if resolutions:
        resolutions_display = ", ".join(resolutions)
    else:
        resolutions_display = "Not Found"

    # Display the collected VirusTotal domain information.
    print("==================================================================")
    print(f"Categories: {categories_display}")
    print(f"Malicious count: {malicious_count}")
    print(f"Suspicious count: {suspicious_count}")
    print(f"Reputation: {reputation}")
    print("")
    print(f"Registrar: {registrar}")
    print(f"A record / IP address: {a_records}")
    print(f"MX record: {mx_records}")
    print(f"Name Server: {name_servers}")
    print(f"Date created: {date_created}")
    print("")
    print(f"SSL certificate issuer: {issuer_display}")
    print(f"SSL valid from: {cert_not_before}")
    print(f"SSL valid until: {cert_not_after}")
    print("")
    print(f"Subdomains: {subdomains_display}")
    print(f"Historical resolutions: {resolutions_display}")
    print("==================================================================")
    print()