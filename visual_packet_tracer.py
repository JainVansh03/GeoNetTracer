import pyshark
import geoip2.database
import csv

# Fallback function for private IPs
def get_private_ip_location(ip):
    """Assign a default location to private IPs"""
    # You can customize this location based on your internal network.
    # Example: Mapping all private IPs to your office location (latitude, longitude).
    private_ip_locations = {
        '192.168.0.0/24': ('40.7128', '-74.0060', 'New York'),  # Example private range for office
        '10.0.0.0/8': ('34.0522', '-118.2437', 'Los Angeles'),  # Example range for another location
    }

    for cidr, location in private_ip_locations.items():
        if ip.startswith(cidr.split('.')[0]):  # Simple check for subnet match
            return location

    # Default fallback for any private IP
    return ('0.0', '0.0', 'Private Network')

def extract_ips(pcap_file):
    """
    Extract source and destination IPs from a PCAP file using pyshark.
    """
    capture = pyshark.FileCapture(pcap_file)
    ip_addresses = []

    for packet in capture:
        try:
            # Extracting source and destination IP addresses
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            ip_addresses.append((src_ip, dst_ip))
        except AttributeError:
            continue  # Skip packets without IP layers

    return ip_addresses

def map_ips_to_locations(ip_addresses, db_path):
    """
    Map IP addresses to geographical locations using GeoLite2 City database.
    """
    locations = []
    reader = geoip2.database.Reader(db_path)

    # Fallback coordinates for private IPs or unresolvable IPs
    fallback_coords = (0.0, 0.0)  # Coordinates for private or unknown IPs
    fallback_location = "Unknown Location"  # Name for private IPs or unknown IPs

    for src_ip, dst_ip in ip_addresses:
        # Check if the source IP is private
        if src_ip.startswith(('10.', '172.', '192.')):
            # Use private IP location fallback
            src_coords = get_private_ip_location(src_ip)
            src_location_name = src_coords[2]
        else:
            try:
                src_location = reader.city(src_ip)
                src_coords = (src_location.location.latitude, src_location.location.longitude)
                src_location_name = src_location.city.name if src_location.city.name else "Unknown Location"
            except geoip2.errors.AddressNotFoundError:
                src_coords = fallback_coords
                src_location_name = fallback_location

        # Check if the destination IP is private
        if dst_ip.startswith(('10.', '172.', '192.')):
            # Use private IP location fallback
            dst_coords = get_private_ip_location(dst_ip)
            dst_location_name = dst_coords[2]
        else:
            try:
                dst_location = reader.city(dst_ip)
                dst_coords = (dst_location.location.latitude, dst_location.location.longitude)
                dst_location_name = dst_location.city.name if dst_location.city.name else "Unknown Location"
            except geoip2.errors.AddressNotFoundError:
                dst_coords = fallback_coords
                dst_location_name = fallback_location

        # Add the location data to the list
        locations.append({
            "src_ip": src_ip,
            "src_lat": src_coords[0],
            "src_lon": src_coords[1],
            "src_location": src_location_name,
            "dst_ip": dst_ip,
            "dst_lat": dst_coords[0],
            "dst_lon": dst_coords[1],
            "dst_location": dst_location_name,
        })

    return locations

def create_csv(locations, output_file):
    """
    Create a CSV file with the geolocation data for source and destination IPs.
    """
    with open(output_file, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["IP", "Latitude", "Longitude", "Location", "Type"])
        writer.writeheader()

        for loc in locations:
            # Write source IP to CSV
            writer.writerow({
                "IP": loc["src_ip"],
                "Latitude": loc["src_lat"],
                "Longitude": loc["src_lon"],
                "Location": loc["src_location"],
                "Type": "Source"
            })

            # Write destination IP to CSV
            writer.writerow({
                "IP": loc["dst_ip"],
                "Latitude": loc["dst_lat"],
                "Longitude": loc["dst_lon"],
                "Location": loc["dst_location"],
                "Type": "Destination"
            })

def main():
    """
    Main function to extract IPs, map them to locations, and generate a CSV file.
    """
    pcap_file = "traffic.pcap"  # Path to your PCAP file
    geo_db_path = "GeoLite2-City.mmdb"  # Path to GeoLite2 City database
    output_csv = "network_traffic1.csv"  # Output CSV file name

    print("Extracting IP addresses from PCAP file...")
    ip_data = extract_ips(pcap_file)

    print("Mapping IP addresses to geographical locations...")
    locations = map_ips_to_locations(ip_data, geo_db_path)

    print("Creating CSV file...")
    create_csv(locations, output_csv)

    print(f"CSV file created successfully: {output_csv}")
    print("You can open this file in a spreadsheet for visualization.")

if __name__ == "__main__":
    main()
