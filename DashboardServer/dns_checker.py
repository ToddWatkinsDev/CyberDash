import dns.resolver
import socket

def check_dns_spoofing(domain):
    """
    Checks for potential DNS spoofing by comparing the IP address
    resolved by the local system against a trusted public DNS server.

    Args:
        domain (str): The domain name to check.

    Returns:
        tuple: A tuple containing a status string ('OK', 'WARNING', or 'FAIL')
               and a descriptive message.
    """
    try:
        # --- Local DNS Resolution ---
        # Get the IP address that the local system resolves to.
        # This uses the DNS server configured on the machine.
        local_ips = socket.gethostbyname_ex(domain)[2]
        local_ips_set = set(local_ips)

        # --- Trusted DNS Resolution ---
        # Perform a DNS lookup using a trusted, public DNS server (Google's DNS)
        # This bypasses the local system's DNS configuration.
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']  # Use Google's Public DNS

        trusted_ips = []
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            trusted_ips.append(rdata.address)
        trusted_ips_set = set(trusted_ips)

        # --- Comparison ---
        if local_ips_set == trusted_ips_set:
            # All local IPs match the trusted IPs.
            return "OK", f"DNS resolution is consistent. IP(s): {', '.join(local_ips)}"
        elif local_ips_set.issubset(trusted_ips_set):
            # Local IPs are a subset of trusted IPs (e.g., local DNS returned one IP, trusted returned multiple).
            return "OK", f"DNS resolution is consistent. IP(s): {', '.join(local_ips)}"
        else:
            # The sets of IP addresses do not match, indicating a potential issue.
            return "WARNING", f"DNS mismatch detected! Local IPs: {', '.join(local_ips)}. Trusted IPs: {', '.join(trusted_ips)}"

    except socket.gaierror as e:
        return "FAIL", f"Could not resolve '{domain}' locally. Error: {e}"
    except dns.exception.DNSException as e:
        return "FAIL", f"Could not resolve '{domain}' via trusted DNS. Error: {e}"
    except Exception as e:
        return "FAIL", f"An unexpected error occurred during DNS check: {e}"
