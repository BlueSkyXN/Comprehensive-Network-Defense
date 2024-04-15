import ipaddress
import argparse

def read_ip_list(file_path):
    ip_list = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line:
                ip_list.append(line)
    return ip_list

def contains_ip(networks, ip):
    for net in networks:
        if ip in net:
            return True
    return False

def filter_ips(ip_list):
    networks = []
    single_ips = []

    # 分类IP和CIDR
    for ip in ip_list:
        try:
            if '/' in ip:
                networks.append(ipaddress.ip_network(ip, strict=False))
            else:
                single_ips.append(ipaddress.ip_address(ip))
        except ValueError:
            continue

    # 筛选不被CIDR包含的独立IP地址
    filtered_ips = [str(ip) for ip in single_ips if not contains_ip(networks, ip)]

    # 添加CIDR网络
    filtered_ips.extend(str(net) for net in networks)

    return filtered_ips

def write_ip_list(file_path, filtered_ips):
    with open(file_path, 'w') as file:
        for ip in filtered_ips:
            file.write(ip + '\n')

def main():
    parser = argparse.ArgumentParser(description="IP List Filter")
    parser.add_argument("-i", "--input", default="SKY-CF-IPLIST.txt", help="Input file name containing IPs and CIDRs")
    args = parser.parse_args()

    ip_list = read_ip_list(args.input)
    filtered_ips = filter_ips(ip_list)
    write_ip_list(args.input, filtered_ips)

if __name__ == "__main__":
    main()
