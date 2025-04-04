import pyshark
import geoip2.database
import csv
import ipaddress  # Import the ipaddress module
import socket  # For reverse DNS lookup

def extract_ips(pcap_file):
    """
    Extract source and destination IPs from a PCAP file using pyshark.
    """
    capture = pyshark.FileCapture(pcap_file)
    ip_addresses = []

    for packet in capture:
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            ip_addresses.append((src_ip, dst_ip))
        except AttributeError:
            continue  # Skip packets without IP layers

    print("Extracted IP Addresses:", ip_addresses)  # Debug print
    return ip_addresses


def get_reverse_dns(ip):
    """
    Perform a reverse DNS lookup to get the domain name for an IP address.
    """
    try:
        domain_name = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        domain_name = "Unknown"  # If no domain is found
    return domain_name


def map_ips_to_locations(ip_addresses, db_path):
    """
    Map IP addresses to geographical locations using GeoLite2 City database.
    """
    locations = []
    reader = geoip2.database.Reader(db_path)

    for src_ip, dst_ip in ip_addresses:
        try:
            # For public IP geolocation using GeoLite2 database
            src_location = reader.city(src_ip) if not is_private_ip(src_ip) else None
            dst_location = reader.city(dst_ip) if not is_private_ip(dst_ip) else None

            # If the IP is private, we can set a placeholder
            src_location_name = src_location.city.name if src_location and src_location.city.name else "Private IP"
            dst_location_name = dst_location.city.name if dst_location and dst_location.city.name else "Private IP"

            # Get reverse DNS (domain name)
            src_domain = get_reverse_dns(src_ip)
            dst_domain = get_reverse_dns(dst_ip)

            locations.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_location": src_location_name,
                "dst_location": dst_location_name,
                "src_domain": src_domain,
                "dst_domain": dst_domain,
            })
        except geoip2.errors.AddressNotFoundError:
            print(f"Geolocation not found for IP: {src_ip} or {dst_ip}")  # Debug print
            continue  # Skip IPs without geolocation data

    print("Mapped Locations:", locations)  # Debug print
    return locations


def is_private_ip(ip):
    """
    Check if an IP address is a private IP.
    """
    # List of private IP ranges (CIDR format)
    private_ip_ranges = [
        ("10.0.0.0", "10.255.255.255"),
        ("172.16.0.0", "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255")
    ]
    # Convert IP to integer
    ip_int = int(ipaddress.IPv4Address(ip))

    for start, end in private_ip_ranges:
        if ip_int >= int(ipaddress.IPv4Address(start)) and ip_int <= int(ipaddress.IPv4Address(end)):
            return True
    return False


def create_csv(locations, output_file):
    """
    Create a CSV file with the geolocation data for source and destination IPs.
    """
    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=["IP", "Location", "Domain", "Type"])
        writer.writeheader()

        for loc in locations:
            # Write source IP to CSV
            writer.writerow({
                "IP": loc["src_ip"],
                "Location": loc["src_location"],
                "Domain": loc["src_domain"],
                "Type": "Source"
            })

            # Write destination IP to CSV
            writer.writerow({
                "IP": loc["dst_ip"],
                "Location": loc["dst_location"],
                "Domain": loc["dst_domain"],
                "Type": "Destination"
            })


def main():
    """
    Main function to extract IPs, map them to locations, and generate a CSV file.
    """
    pcap_file = "traffic.pcap"  # Path to your PCAP file
    geo_db_path = "GeoLite2-City.mmdb"  # Path to GeoLite2 City database
    output_csv = "network_traffic_with_location.csv"  # Output CSV file name

    print("Extracting IP addresses from PCAP file...")
    ip_data = extract_ips(pcap_file)

    print("Mapping IP addresses to geographical locations...")
    locations = map_ips_to_locations(ip_data, geo_db_path)

    print("Creating CSV file with geolocation data...")
    create_csv(locations, output_csv)

    print(f"CSV file created successfully: {output_csv}")
    print("You can open this file to view the geolocation and domain data of network traffic.")


if __name__ == "__main__":
    main()
