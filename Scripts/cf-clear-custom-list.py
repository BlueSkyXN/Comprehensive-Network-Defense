#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare Custom IP List Cleaner
清空 Cloudflare 自定义 IP 列表工具

Author: blueskyxn
Repository: https://github.com/BlueSkyXN/Comprehensive-Network-Defense/tree/master/Scripts
License: MIT

使用说明:
1. 设置环境变量或创建配置文件
2. 运行脚本清空指定的自定义列表

环境变量方式:
    export CF_EMAIL="your-email@example.com"
    export CF_API_KEY="your-api-key"
    export CF_ACCOUNT_ID="your-account-id"
    export CF_LIST_ID="your-list-id"
    python3 CLEAN-CF-Custom-IPs-LIST.py

配置文件方式:
    python3 CLEAN-CF-Custom-IPs-LIST.py --config config.json

命令行参数方式:
    python3 CLEAN-CF-Custom-IPs-LIST.py --email xxx --api-key xxx --account-id xxx --list-id xxx
"""

import os
import sys
import json
import argparse
import requests
from typing import Dict, Optional


class CloudflareListCleaner:
    """Cloudflare 自定义列表清理器"""
    
    def __init__(self, email: str, api_key: str, account_id: str, list_id: str):
        """
        初始化清理器
        
        Args:
            email: Cloudflare 账户邮箱
            api_key: Cloudflare API 密钥
            account_id: Cloudflare 账户 ID
            list_id: 要清空的列表 ID
        """
        self.email = email
        self.api_key = api_key
        self.account_id = account_id
        self.list_id = list_id
        
        self.headers = {
            'X-Auth-Email': self.email,
            'X-Auth-Key': self.api_key,
            'Content-Type': 'application/json'
        }
        
        self.api_url = f"https://api.cloudflare.com/client/v4/accounts/{self.account_id}/rules/lists/{self.list_id}/items"
    
    def clean_list(self) -> bool:
        """
        清空自定义列表
        
        Returns:
            bool: 操作是否成功
        """
        try:
            print(f"正在清空列表 ID: {self.list_id}...")
            
            # 发送 PUT 请求，空数组表示清空列表
            response = requests.put(self.api_url, headers=self.headers, json=[])
            
            print(f"状态码: {response.status_code}")
            
            # 解析响应
            result = response.json()
            
            if response.status_code == 200:
                print("✅ 列表已成功清空！")
                
                # 检查是否有操作ID（异步操作）
                if 'result' in result and 'operation_id' in result['result']:
                    operation_id = result['result']['operation_id']
                    print(f"操作 ID: {operation_id}")
                    print("注意: 这是一个异步操作，可以通过操作 ID 查询状态")
                
                return True
            else:
                print(f"❌ 清空列表失败")
                self._print_error(result)
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ 网络请求失败: {e}")
            return False
        except Exception as e:
            print(f"❌ 发生未知错误: {e}")
            return False
    
    def _print_error(self, response_data: Dict):
        """打印错误信息"""
        if 'errors' in response_data:
            for error in response_data['errors']:
                print(f"错误代码: {error.get('code', 'N/A')}")
                print(f"错误信息: {error.get('message', 'N/A')}")
        else:
            print(f"响应内容: {response_data}")


def load_config_from_env() -> Optional[Dict[str, str]]:
    """从环境变量加载配置"""
    config = {}
    
    required_vars = {
        'CF_EMAIL': 'email',
        'CF_API_KEY': 'api_key',
        'CF_ACCOUNT_ID': 'account_id',
        'CF_LIST_ID': 'list_id'
    }
    
    for env_var, config_key in required_vars.items():
        value = os.environ.get(env_var)
        if value:
            config[config_key] = value
    
    # 检查是否所有必需的配置都存在
    if len(config) == len(required_vars):
        return config
    
    return None


def load_config_from_file(file_path: str) -> Optional[Dict[str, str]]:
    """从配置文件加载配置"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # 验证必需的配置项
        required_keys = ['email', 'api_key', 'account_id', 'list_id']
        for key in required_keys:
            if key not in config:
                print(f"❌ 配置文件缺少必需的配置项: {key}")
                return None
        
        return config
    except FileNotFoundError:
        print(f"❌ 配置文件不存在: {file_path}")
        return None
    except json.JSONDecodeError:
        print(f"❌ 配置文件格式错误，请确保是有效的 JSON 格式")
        return None
    except Exception as e:
        print(f"❌ 读取配置文件失败: {e}")
        return None


def create_sample_config():
    """创建示例配置文件"""
    sample_config = {
        "email": "your-email@example.com",
        "api_key": "your-cloudflare-api-key",
        "account_id": "your-account-id",
        "list_id": "your-list-id"
    }
    
    with open('config.example.json', 'w', encoding='utf-8') as f:
        json.dump(sample_config, f, indent=2, ensure_ascii=False)
    
    print("✅ 已创建示例配置文件: config.example.json")
    print("请将其重命名为 config.json 并填入您的实际配置信息")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='清空 Cloudflare 自定义 IP 列表',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用环境变量
  export CF_EMAIL="your-email@example.com"
  export CF_API_KEY="your-api-key"
  export CF_ACCOUNT_ID="your-account-id"
  export CF_LIST_ID="your-list-id"
  python3 %(prog)s

  # 使用配置文件
  python3 %(prog)s --config config.json

  # 使用命令行参数
  python3 %(prog)s --email xxx --api-key xxx --account-id xxx --list-id xxx

  # 创建示例配置文件
  python3 %(prog)s --create-sample
        """
    )
    
    parser.add_argument('--config', help='配置文件路径')
    parser.add_argument('--email', help='Cloudflare 账户邮箱')
    parser.add_argument('--api-key', help='Cloudflare API 密钥')
    parser.add_argument('--account-id', help='Cloudflare 账户 ID')
    parser.add_argument('--list-id', help='要清空的列表 ID')
    parser.add_argument('--create-sample', action='store_true', 
                        help='创建示例配置文件')
    
    args = parser.parse_args()
    
    # 如果请求创建示例配置
    if args.create_sample:
        create_sample_config()
        return
    
    config = None
    
    # 优先级: 命令行参数 > 配置文件 > 环境变量
    if args.email and args.api_key and args.account_id and args.list_id:
        config = {
            'email': args.email,
            'api_key': args.api_key,
            'account_id': args.account_id,
            'list_id': args.list_id
        }
        print("使用命令行参数配置")
    elif args.config:
        config = load_config_from_file(args.config)
        if config:
            print(f"使用配置文件: {args.config}")
    else:
        config = load_config_from_env()
        if config:
            print("使用环境变量配置")
    
    if not config:
        print("\n❌ 未找到有效的配置信息！\n")
        print("请使用以下方式之一提供配置:")
        print("1. 设置环境变量 (CF_EMAIL, CF_API_KEY, CF_ACCOUNT_ID, CF_LIST_ID)")
        print("2. 使用配置文件: python3 {} --config config.json".format(sys.argv[0]))
        print("3. 使用命令行参数: python3 {} --email xxx --api-key xxx --account-id xxx --list-id xxx".format(sys.argv[0]))
        print("\n运行 python3 {} --help 查看详细帮助".format(sys.argv[0]))
        print("运行 python3 {} --create-sample 创建示例配置文件".format(sys.argv[0]))
        sys.exit(1)
    
    # 创建清理器实例并执行清理
    cleaner = CloudflareListCleaner(
        email=config['email'],
        api_key=config['api_key'],
        account_id=config['account_id'],
        list_id=config['list_id']
    )
    
    success = cleaner.clean_list()
    
    if success:
        print("\n✅ 操作完成！")
    else:
        print("\n❌ 操作失败，请检查配置和错误信息")
        sys.exit(1)


if __name__ == '__main__':
    main()
