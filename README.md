# Whois-Lookup-Tool
Use this tool to look up domain information using the VirusTotal API.

When you run the script, you will be prompted to enter your VirusTotal API key. After that, enter each domain you want to look up.

You can continue entering domains one at a time. When you are finished, enter `Q` to exit the script.

Example output:

```text
==================================================================
Categories: Example Category
Malicious count: 0
Suspicious count: 0
Reputation: 0

Registrar: EXAMPLE REGISTRAR
A record / IP address: 192.0.2.10
MX record: mail.example.com
Name Server: ns1.example.com, ns2.example.com
Date created: 2024-01-01 00:00:00 UTC

SSL certificate issuer: C=US, O=Example Certificate Authority, CN=Example TLS CA
SSL valid from: 2024-01-01 00:00:00
SSL valid until: 2025-01-01 00:00:00

Subdomains: app.example.com, test.example.com, dev.example.com
Historical resolutions: 192.0.2.10 (2024-01-01 00:00:00 UTC), 198.51.100.25 (2023-06-01 00:00:00 UTC), 203.0.113.50 (2022-01-01 00:00:00 UTC)
==================================================================
```
