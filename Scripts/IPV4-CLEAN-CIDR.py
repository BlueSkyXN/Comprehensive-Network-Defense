#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP地址清洗工具
用于处理DDoS攻击IP列表，将同一C段多个IP合并为/24网段
"""

import ipaddress
import sys
from collections import defaultdict
from pathlib import Path


def read_ip_list(file_path):
    """
    从文件中读取IP地址列表
    
    Args:
        file_path: IP列表文件路径
        
    Returns:
        list: 有效的IP地址列表
    """
    ip_list = []
    invalid_ips = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                ip_str = line.strip()
                if not ip_str:  # 跳过空行
                    continue
                    
                try:
                    # 验证IP地址有效性
                    ip = ipaddress.IPv4Address(ip_str)
                    ip_list.append(str(ip))
                except ipaddress.AddressValueError:
                    invalid_ips.append(f"第{line_num}行: {ip_str}")
                    
    except FileNotFoundError:
        print(f"错误: 文件 {file_path} 不存在")
        sys.exit(1)
    except Exception as e:
        print(f"读取文件时发生错误: {e}")
        sys.exit(1)
    
    # 报告无效IP
    if invalid_ips:
        print(f"发现 {len(invalid_ips)} 个无效IP地址:")
        for invalid_ip in invalid_ips[:10]:  # 最多显示10个
            print(f"  {invalid_ip}")
        if len(invalid_ips) > 10:
            print(f"  ... 还有 {len(invalid_ips) - 10} 个无效IP")
        print()
    
    return ip_list


def group_by_c_segment(ip_list):
    """
    按C段分组IP地址
    
    Args:
        ip_list: IP地址列表
        
    Returns:
        dict: {c_segment: [ip_list]}
    """
    c_segments = defaultdict(list)
    
    for ip_str in ip_list:
        ip = ipaddress.IPv4Address(ip_str)
        # 获取C段网络 (前24位)
        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
        c_segment = str(network.network_address)  # 例如: 192.168.1.0
        c_segments[c_segment].append(ip_str)
    
    return c_segments


def clean_ip_list(ip_list):
    """
    清洗IP列表：同一C段>=2个IP时合并为/24，否则保留原IP
    
    Args:
        ip_list: 原始IP地址列表
        
    Returns:
        tuple: (cleaned_results, statistics)
    """
    # 去重
    unique_ips = list(set(ip_list))
    print(f"原始IP数量: {len(ip_list)}")
    print(f"去重后IP数量: {len(unique_ips)}")
    
    # 按C段分组
    c_segments = group_by_c_segment(unique_ips)
    
    cleaned_results = []
    statistics = {
        'total_c_segments': len(c_segments),
        'merged_c_segments': 0,
        'single_ips': 0,
        'original_count': len(unique_ips),
        'final_count': 0
    }
    
    # 处理每个C段
    for c_segment, ips in c_segments.items():
        if len(ips) >= 2:
            # 同一C段有2个或以上IP，合并为/24
            network = f"{c_segment}/24"
            cleaned_results.append(network)
            statistics['merged_c_segments'] += 1
            print(f"合并C段 {c_segment} ({len(ips)}个IP) -> {network}")
        else:
            # 单个IP保留
            cleaned_results.append(ips[0])
            statistics['single_ips'] += 1
    
    statistics['final_count'] = len(cleaned_results)
    return cleaned_results, statistics


def save_results(results, output_file, statistics):
    """
    保存清洗结果到文件
    
    Args:
        results: 清洗后的结果列表
        output_file: 输出文件路径
        statistics: 统计信息
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            # 写入统计信息作为注释
            f.write(f"# IP清洗结果统计\n")
            f.write(f"# 原始IP数量: {statistics['original_count']}\n")
            f.write(f"# 清洗后数量: {statistics['final_count']}\n")
            f.write(f"# 总C段数量: {statistics['total_c_segments']}\n")
            f.write(f"# 合并的C段: {statistics['merged_c_segments']}\n")
            f.write(f"# 保留的单IP: {statistics['single_ips']}\n")
            f.write(f"# 压缩比: {statistics['original_count']/statistics['final_count']:.2f}:1\n")
            f.write(f"#\n")
            
            # 分别输出网段和单IP，便于使用
            networks = [item for item in results if '/' in item]
            single_ips = [item for item in results if '/' not in item]
            
            if networks:
                f.write("# === 网段列表 ===\n")
                for network in sorted(networks, key=lambda x: ipaddress.IPv4Network(x)):
                    f.write(f"{network}\n")
                f.write("\n")
            
            if single_ips:
                f.write("# === 单IP列表 ===\n")
                for ip in sorted(single_ips, key=lambda x: ipaddress.IPv4Address(x)):
                    f.write(f"{ip}\n")
        
        print(f"\n结果已保存到: {output_file}")
        
    except Exception as e:
        print(f"保存文件时发生错误: {e}")


def print_statistics(statistics):
    """打印统计信息"""
    print("\n" + "="*50)
    print("清洗统计结果:")
    print("="*50)
    print(f"原始IP数量:     {statistics['original_count']}")
    print(f"清洗后数量:     {statistics['final_count']}")
    print(f"压缩比:         {statistics['original_count']/statistics['final_count']:.2f}:1")
    print(f"总C段数量:      {statistics['total_c_segments']}")
    print(f"合并的C段:      {statistics['merged_c_segments']}")
    print(f"保留的单IP:     {statistics['single_ips']}")
    print("="*50)


def main():
    """主函数"""
    # 检查命令行参数
    if len(sys.argv) != 2:
        print("使用方法: python IPV4-CLEAN-CIDR.py <IP列表文件>")
        print("示例: python IPV4-CLEAN-CIDR.py ddos_ips.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    # 生成输出文件名
    input_path = Path(input_file)
    output_file = input_path.parent / f"{input_path.stem}_cleaned{input_path.suffix}"
    
    print(f"开始处理IP清洗任务...")
    print(f"输入文件: {input_file}")
    print(f"输出文件: {output_file}")
    print("-" * 50)
    
    # 读取IP列表
    ip_list = read_ip_list(input_file)
    if not ip_list:
        print("没有找到有效的IP地址")
        sys.exit(1)
    
    # 清洗IP列表
    cleaned_results, statistics = clean_ip_list(ip_list)
    
    # 保存结果
    save_results(cleaned_results, output_file, statistics)
    
    # 打印统计信息
    print_statistics(statistics)


if __name__ == "__main__":
    main()