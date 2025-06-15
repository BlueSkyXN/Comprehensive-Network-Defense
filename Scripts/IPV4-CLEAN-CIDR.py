#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强版IP地址清洗工具
支持混合输入：IPv4地址 + CIDR网段，智能去重和合并
用于处理DDoS攻击IP列表，将同一C段多个IP合并为/24网段
"""

import ipaddress
import sys
from collections import defaultdict
from pathlib import Path


def parse_input_line(line):
    """
    解析输入行，区分单IP和CIDR网段
    
    Args:
        line: 输入行内容
        
    Returns:
        tuple: (type, object) - ('ip', IPv4Address) 或 ('network', IPv4Network) 或 (None, None)
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None, None
    
    try:
        # 尝试解析为CIDR网段
        if '/' in line:
            network = ipaddress.IPv4Network(line, strict=False)
            return 'network', network
        else:
            # 尝试解析为单IP
            ip = ipaddress.IPv4Address(line)
            return 'ip', ip
    except ipaddress.AddressValueError:
        return 'invalid', line


def read_mixed_ip_list(file_path):
    """
    从文件中读取混合IP地址列表（包含单IP和CIDR）
    
    Args:
        file_path: IP列表文件路径
        
    Returns:
        tuple: (ip_list, network_list, invalid_list)
    """
    ip_list = []
    network_list = []
    invalid_list = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                entry_type, entry_obj = parse_input_line(line)
                
                if entry_type == 'ip':
                    ip_list.append(entry_obj)
                elif entry_type == 'network':
                    network_list.append(entry_obj)
                elif entry_type == 'invalid':
                    invalid_list.append(f"第{line_num}行: {entry_obj}")
                    
    except FileNotFoundError:
        print(f"错误: 文件 {file_path} 不存在")
        sys.exit(1)
    except Exception as e:
        print(f"读取文件时发生错误: {e}")
        sys.exit(1)
    
    # 报告无效条目
    if invalid_list:
        print(f"发现 {len(invalid_list)} 个无效条目:")
        for invalid_entry in invalid_list[:10]:  # 最多显示10个
            print(f"  {invalid_entry}")
        if len(invalid_list) > 10:
            print(f"  ... 还有 {len(invalid_list) - 10} 个无效条目")
        print()
    
    return ip_list, network_list, invalid_list


def merge_overlapping_networks(network_list):
    """
    合并重叠的网段
    
    Args:
        network_list: 网络对象列表
        
    Returns:
        list: 合并后的网络列表
    """
    if not network_list:
        return []
    
    # 按网络地址排序
    sorted_networks = sorted(set(network_list))
    merged = [sorted_networks[0]]
    
    for current in sorted_networks[1:]:
        last_merged = merged[-1]
        
        # 检查是否有重叠或相邻
        if (current.network_address <= last_merged.broadcast_address + 1 and
            current.broadcast_address >= last_merged.network_address):
            
            # 合并网段：选择更大的网段
            if current.supernet_of(last_merged):
                merged[-1] = current
            elif last_merged.supernet_of(current):
                continue  # 保留原有的更大网段
            else:
                # 尝试找到包含两者的最小网段
                try:
                    # 简单处理：如果是同一个/24内的，就合并为/24
                    if (current.network_address.packed[:3] == 
                        last_merged.network_address.packed[:3]):
                        # 构建C段网络地址
                        c_segment_bytes = current.network_address.packed[:3] + b'\x00'
                        c_segment_ip = ipaddress.IPv4Address(c_segment_bytes)
                        combined_network = ipaddress.IPv4Network(f"{c_segment_ip}/24")
                        merged[-1] = combined_network
                    else:
                        merged.append(current)
                except:
                    merged.append(current)
        else:
            merged.append(current)
    
    return merged


def filter_ips_by_networks(ip_list, network_list):
    """
    过滤掉已被网段覆盖的单IP
    
    Args:
        ip_list: IP地址列表
        network_list: 网络对象列表
        
    Returns:
        tuple: (filtered_ips, covered_ips_count)
    """
    if not network_list:
        return ip_list, 0
    
    filtered_ips = []
    covered_count = 0
    
    for ip in ip_list:
        is_covered = False
        for network in network_list:
            if ip in network:
                is_covered = True
                covered_count += 1
                break
        
        if not is_covered:
            filtered_ips.append(ip)
    
    return filtered_ips, covered_count


def group_ips_by_c_segment(ip_list):
    """
    按C段分组IP地址
    
    Args:
        ip_list: IP地址列表
        
    Returns:
        dict: {network_address: [ip_list]}
    """
    c_segments = defaultdict(list)
    
    for ip in ip_list:
        # 获取C段网络 (前24位)
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        c_segments[network.network_address].append(ip)
    
    return c_segments


def clean_mixed_ip_list(ip_list, network_list):
    """
    清洗混合IP列表：处理网段重叠，合并C段
    
    Args:
        ip_list: 原始IP地址列表
        network_list: 原始网络列表
        
    Returns:
        tuple: (cleaned_results, statistics)
    """
    print(f"原始单IP数量: {len(ip_list)}")
    print(f"原始网段数量: {len(network_list)}")
    
    # 去重
    unique_ips = list(set(ip_list))
    unique_networks = list(set(network_list))
    
    print(f"去重后单IP数量: {len(unique_ips)}")
    print(f"去重后网段数量: {len(unique_networks)}")
    
    # 合并重叠的网段
    merged_networks = merge_overlapping_networks(unique_networks)
    print(f"合并重叠后网段数量: {len(merged_networks)}")
    
    # 过滤掉被网段覆盖的单IP
    filtered_ips, covered_count = filter_ips_by_networks(unique_ips, merged_networks)
    print(f"被现有网段覆盖的单IP: {covered_count}个")
    print(f"剩余待处理单IP: {len(filtered_ips)}个")
    
    # 对剩余单IP按C段分组
    c_segments = group_ips_by_c_segment(filtered_ips)
    
    # 生成最终结果
    final_results = []
    new_c24_networks = 0
    single_ips = 0
    
    # 添加已有的网段
    for network in merged_networks:
        final_results.append(str(network))
    
    # 处理C段分组
    for network_addr, ips in c_segments.items():
        c24_network = ipaddress.IPv4Network(f"{network_addr}/24")
        
        # 检查这个C段是否已被现有网段覆盖
        is_covered = False
        for existing_network in merged_networks:
            if c24_network.subnet_of(existing_network):
                is_covered = True
                break
        
        if not is_covered:
            if len(ips) >= 2:
                # 同一C段有2个或以上IP，合并为/24
                new_network = f"{network_addr}/24"
                final_results.append(new_network)
                new_c24_networks += 1
                print(f"新建C段 {network_addr} ({len(ips)}个IP) -> {new_network}")
            else:
                # 单个IP保留
                final_results.append(str(ips[0]))
                single_ips += 1
    
    # 统计信息
    statistics = {
        'original_ips': len(ip_list),
        'original_networks': len(network_list),
        'unique_ips': len(unique_ips),
        'unique_networks': len(unique_networks),
        'merged_networks': len(merged_networks),
        'covered_ips': covered_count,
        'new_c24_networks': new_c24_networks,
        'final_single_ips': single_ips,
        'final_count': len(final_results),
        'compression_ratio': (len(ip_list) + len(network_list)) / len(final_results) if final_results else 1
    }
    
    return final_results, statistics


def save_enhanced_results(results, output_file, statistics):
    """
    保存增强版清洗结果到文件
    
    Args:
        results: 清洗后的结果列表
        output_file: 输出文件路径
        statistics: 统计信息
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # 写入详细统计信息
            f.write(f"# IP清洗结果统计 (增强版)\n")
            f.write(f"# 原始单IP数量: {statistics['original_ips']}\n")
            f.write(f"# 原始网段数量: {statistics['original_networks']}\n")
            f.write(f"# 去重后单IP: {statistics['unique_ips']}\n")
            f.write(f"# 去重后网段: {statistics['unique_networks']}\n")
            f.write(f"# 合并后网段: {statistics['merged_networks']}\n")
            f.write(f"# 被覆盖单IP: {statistics['covered_ips']}\n")
            f.write(f"# 新建C段: {statistics['new_c24_networks']}\n")
            f.write(f"# 最终单IP: {statistics['final_single_ips']}\n")
            f.write(f"# 最终总数: {statistics['final_count']}\n")
            f.write(f"# 压缩比: {statistics['compression_ratio']:.2f}:1\n")
            f.write(f"#\n")
            
            # 分类输出
            networks = []
            single_ips = []
            
            for item in results:
                if '/' in item:
                    networks.append(item)
                else:
                    single_ips.append(item)
            
            if networks:
                f.write("# === 网段列表 ===\n")
                # 按网络大小排序
                try:
                    sorted_networks = sorted(networks, key=lambda x: ipaddress.IPv4Network(x))
                    for network in sorted_networks:
                        f.write(f"{network}\n")
                except:
                    for network in sorted(networks):
                        f.write(f"{network}\n")
                f.write("\n")
            
            if single_ips:
                f.write("# === 单IP列表 ===\n")
                try:
                    sorted_ips = sorted(single_ips, key=lambda x: ipaddress.IPv4Address(x))
                    for ip in sorted_ips:
                        f.write(f"{ip}\n")
                except:
                    for ip in sorted(single_ips):
                        f.write(f"{ip}\n")
        
        print(f"\n结果已保存到: {output_file}")
        
    except Exception as e:
        print(f"保存文件时发生错误: {e}")


def print_enhanced_statistics(statistics):
    """打印增强版统计信息"""
    print("\n" + "="*60)
    print("增强版IP清洗统计结果:")
    print("="*60)
    print(f"原始条目:       单IP {statistics['original_ips']} + 网段 {statistics['original_networks']} = {statistics['original_ips'] + statistics['original_networks']}")
    print(f"去重后:         单IP {statistics['unique_ips']} + 网段 {statistics['unique_networks']} = {statistics['unique_ips'] + statistics['unique_networks']}")
    print(f"处理结果:")
    print(f"  - 合并重叠网段: {statistics['merged_networks']}")
    print(f"  - 被覆盖单IP:   {statistics['covered_ips']}")
    print(f"  - 新建C段:      {statistics['new_c24_networks']}")
    print(f"  - 保留单IP:     {statistics['final_single_ips']}")
    print(f"最终总数:       {statistics['final_count']}")
    print(f"压缩比:         {statistics['compression_ratio']:.2f}:1")
    print("="*60)


def main():
    """主函数"""
    # 检查命令行参数
    if len(sys.argv) != 2:
        print("使用方法: python IPV4-CLEAN-CIDR.py <IP列表文件>")
        print("示例: python IPV4-CLEAN-CIDR.py ddos_ips.txt")
        print("")
        print("支持混合输入格式:")
        print("  - 单IP: 192.168.1.10")
        print("  - CIDR: 192.168.1.0/24")
        print("  - 混合: 可同时包含单IP和CIDR")
        print("  - 注释: 以#开头的行会被忽略")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # 生成输出文件名
    input_path = Path(input_file)
    output_file = input_path.parent / f"{input_path.stem}_enhanced_cleaned{input_path.suffix}"
    
    print(f"开始处理增强版IP清洗任务...")
    print(f"输入文件: {input_file}")
    print(f"输出文件: {output_file}")
    print("-" * 50)
    
    # 读取混合IP列表
    ip_list, network_list, invalid_list = read_mixed_ip_list(input_file)
    
    if not ip_list and not network_list:
        print("没有找到有效的IP地址或网段")
        sys.exit(1)
    
    # 清洗混合IP列表
    cleaned_results, statistics = clean_mixed_ip_list(ip_list, network_list)
    
    # 保存结果
    save_enhanced_results(cleaned_results, output_file, statistics)
    
    # 打印统计信息
    print_enhanced_statistics(statistics)


if __name__ == "__main__":
    main()