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
                network = ipaddress.ip_network(ip, strict=False)
                networks.append(network)
                print(f"添加CIDR网络：{network}")
            else:
                ip_obj = ipaddress.ip_address(ip)
                single_ips.append(ip_obj)
                print(f"添加独立IP地址：{ip_obj}")
        except ValueError as e:
            print(f"无效的IP或网络：{ip}, 错误：{e}")

    # 筛选不被CIDR包含的独立IP地址
    filtered_ips = []
    for ip in single_ips:
        if not contains_ip(networks, ip):
            filtered_ips.append(str(ip))
            print(f"保留未被覆盖的IP：{ip}")
        else:
            print(f"过滤掉被覆盖的IP：{ip}")

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

    print("开始读取IP列表...")
    ip_list = read_ip_list(args.input)
    print("开始过滤IP列表...")
    filtered_ips = filter_ips(ip_list)
    print("写入过滤后的IP列表...")
    write_ip_list(args.input, filtered_ips)
    print("处理完成。")

if __name__ == "__main__":
    main()
