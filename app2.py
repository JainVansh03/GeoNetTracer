import pyshark
import geoip2.database
import geoip2.database
import ipaddress

# Define a function to check if an IP is private
def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private

def map_ips_to_locations(ip_addresses, db_path):
    """
    Map IP addresses to geographical locations using GeoLite2 City database.
    """
    locations = []
    reader = geoip2.database.Reader(db_path)

    for src_ip, dst_ip in ip_addresses:
        # Skip private IPs
        if is_private_ip(src_ip) or is_private_ip(dst_ip):
            print(f"Skipping private IP: {src_ip} or {dst_ip}")
            continue

        try:
            src_location = reader.city(src_ip)
            dst_location = reader.city(dst_ip)

            print(f"Geolocation for {src_ip}: {src_location.location.latitude}, {src_location.location.longitude}")
            print(f"Geolocation for {dst_ip}: {dst_location.location.latitude}, {dst_location.location.longitude}")

            locations.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_coords": (src_location.location.latitude, src_location.location.longitude),
                "dst_coords": (dst_location.location.latitude, dst_location.location.longitude),
            })
        except geoip2.errors.AddressNotFoundError:
            print(f"Geolocation not found for IP: {src_ip} or {dst_ip}")  # Debug print
            continue  # Skip IPs without geolocation data

    print("Mapped Locations:", locations)  # Debug print
    return locations

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
def map_ips_to_locations(ip_addresses, db_path):
    """
    Map IP addresses to geographical locations using GeoLite2 City database.
    """
    locations = []
    reader = geoip2.database.Reader(db_path)

    for src_ip, dst_ip in ip_addresses:
        try:
            src_location = reader.city(src_ip)
            dst_location = reader.city(dst_ip)

            print(f"Geolocation for {src_ip}: {src_location.location.latitude}, {src_location.location.longitude}")
            print(f"Geolocation for {dst_ip}: {dst_location.location.latitude}, {dst_location.location.longitude}")

            locations.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_coords": (src_location.location.latitude, src_location.location.longitude),
                "dst_coords": (dst_location.location.latitude, dst_location.location.longitude),
            })
        except geoip2.errors.AddressNotFoundError:
            print(f"Geolocation not found for IP: {src_ip} or {dst_ip}")  # Debug print
            continue  # Skip IPs without geolocation data

    print("Mapped Locations:", locations)  # Debug print
    return locations

def main():
    pcap_file = "traffic.pcap"  # Path to your PCAP file
    geo_db_path = "GeoLite2-City.mmdb"  # Path to the GeoLite2 City database

    # Extract IP addresses from the PCAP file
    ip_addresses = extract_ips(pcap_file)

    # Map IP addresses to geographical locations
    locations = map_ips_to_locations(ip_addresses, geo_db_path)

    # Print or process the locations as needed
    print(locations)

if __name__ == "__main__":
    main()
