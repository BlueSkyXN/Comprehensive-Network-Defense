import sys
import ipaddress

def convert_to_cidr24(ip):
    """ Convert IP to CIDR /24 network. """
    return ipaddress.ip_network(ip + '/24', strict=False)

def process_ips(input_file, output_file):
    """ Read IPs from input_file, convert, deduplicate, sort, and write to output_file. """
    try:
        with open(input_file, 'r') as file:
            # Read IPs, convert to /24, and deduplicate using set comprehension
            ips = set(convert_to_cidr24(line.strip()) for line in file)

        # Sort IPs
        sorted_ips = sorted(ips, key=lambda x: int(x.network_address))

        # Write sorted and unique IPs to the output file
        with open(output_file, 'w') as file:
            for ip in sorted_ips:
                file.write(str(ip) + '\n')

        print(f"Processed IPs have been saved to {output_file}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    process_ips(input_file, output_file)

