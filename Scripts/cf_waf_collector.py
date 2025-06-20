#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare防火墙事件分层采集器 - 通用版本
支持API级规则ID筛选、地区筛选、多种导出格式

项目地址: https://github.com/BlueSkyXN/Comprehensive-Network-Defense/tree/master/Scripts
作者: BlueSkyXN
版本: v2.0.0
更新时间: 2025-06-20

功能特性:
- 支持API级规则ID和地区筛选
- 自动处理大数据集（Excel行数限制自动切换CSV）
- 二分法优化查询性能
- 支持并行处理
- 详细的配置选项和错误处理

使用前请确保：
1. 拥有有效的Cloudflare API密钥
2. 具有目标Zone的读取权限
3. 已安装所需依赖: pip install pandas requests openpyxl
"""

import pandas as pd
import requests
from datetime import datetime, timedelta, timezone
import time
import logging
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple
import os
import sys

# ================================
# 配置参数区域
# ================================

class Config:
    """
    配置参数类 - 请根据实际需求修改以下参数
    
    ⚠️ 重要提醒：
    1. 请妥善保管您的API密钥，不要泄露给他人
    2. 建议使用环境变量存储敏感信息
    3. 首次使用请先进行小范围测试
    """
    
    # ===== Cloudflare API 配置 =====
    # 获取方式：Cloudflare Dashboard -> My Profile -> API Tokens
    CLOUDFLARE_EMAIL = 'your-email@example.com'          # 您的Cloudflare账户邮箱
    CLOUDFLARE_API_KEY = 'your-global-api-key-here'      # 全局API密钥（推荐使用API Token）
    CLOUDFLARE_ZONE_ID = 'your-zone-id-here'             # 目标域名的Zone ID
    
    # ===== 时间范围配置 (本地时间 UTC+8) =====
    # 格式: "YYYY-MM-DD HH:MM:SS"
    LOCAL_START_TIME = "2025-06-20 09:00:00"             # 查询开始时间
    LOCAL_END_TIME = "2025-06-20 12:00:00"               # 查询结束时间
    
    # ===== 主机筛选配置 =====
    TARGET_HOST = "example.com"                          # 目标主机名，空字符串表示不筛选
    
    # ===== 规则ID筛选配置 =====
    TARGET_RULE_ID = ""                                  # WAF规则ID，空字符串表示不筛选
    ENABLE_RULE_ID_FILTER = False                        # 是否启用API级规则ID筛选
    
    # ===== 地区筛选配置 =====
    FILTER_COUNTRIES = ["CN", "HK"]                      # 地区筛选，使用ISO国家代码
    ENABLE_COUNTRY_FILTER = False                        # 是否启用地区筛选
    
    # 常用地区代码参考：
    # CN: 中国大陆  HK: 香港     TW: 台湾     SG: 新加坡
    # JP: 日本      KR: 韩国     US: 美国     GB: 英国
    # DE: 德国      FR: 法国     RU: 俄罗斯   AU: 澳大利亚
    
    # ===== 其他筛选配置 =====
    FILTER_ACTIONS = []                                  # 动作筛选，如 ["block", "challenge", "log"]
    EXCLUDE_ALLOW_ACTIONS = False                        # 是否排除allow动作
    
    # ===== API 性能配置 =====
    API_LIMIT = 5000                                     # API单次查询限制
    API_SAFE_THRESHOLD = 0.98                            # 安全阈值（98%）
    REQUEST_RETRY_COUNT = 3                              # 重试次数
    REQUEST_RETRY_DELAY = 5                              # 重试延迟（秒）
    REQUEST_DELAY = 0.8                                  # 请求间延迟（秒）
    
    # ===== 二分法优化配置 =====
    MIN_WINDOW_SECONDS = 60                              # 最小时间窗口（秒）
    MAX_WINDOW_SECONDS = 60                              # 最大时间窗口（秒）
    BINARY_SEARCH_MAX_ITERATIONS = 12                    # 二分法最大迭代次数
    BINARY_SEARCH_PRECISION_SECONDS = 60                 # 二分法精度（秒）
    
    # ===== 并发配置 =====
    ENABLE_PARALLEL = True                               # 是否启用并行处理
    MAX_CONCURRENT_HOURS = 3                             # 最大并发小时数

    # ===== 输出配置 =====
    OUTPUT_DIR = "output"                                # 输出目录
    LOG_DIR = "logs"                                     # 日志目录

    @classmethod
    def load_from_env(cls):
        """从环境变量加载配置（推荐方式）"""
        # 从环境变量加载敏感信息
        cls.CLOUDFLARE_EMAIL = os.getenv('CF_EMAIL', cls.CLOUDFLARE_EMAIL)
        cls.CLOUDFLARE_API_KEY = os.getenv('CF_API_KEY', cls.CLOUDFLARE_API_KEY)
        cls.CLOUDFLARE_ZONE_ID = os.getenv('CF_ZONE_ID', cls.CLOUDFLARE_ZONE_ID)
        
        # 从环境变量加载其他配置
        cls.TARGET_HOST = os.getenv('CF_TARGET_HOST', cls.TARGET_HOST)
        cls.TARGET_RULE_ID = os.getenv('CF_RULE_ID', cls.TARGET_RULE_ID)
        
        # 地区筛选
        countries_env = os.getenv('CF_COUNTRIES', '')
        if countries_env:
            cls.FILTER_COUNTRIES = [c.strip().upper() for c in countries_env.split(',')]
        
        # 布尔值配置
        cls.ENABLE_RULE_ID_FILTER = os.getenv('CF_ENABLE_RULE_FILTER', 'false').lower() == 'true'
        cls.ENABLE_COUNTRY_FILTER = os.getenv('CF_ENABLE_COUNTRY_FILTER', 'false').lower() == 'true'
        cls.ENABLE_PARALLEL = os.getenv('CF_ENABLE_PARALLEL', 'true').lower() == 'true'

    @classmethod
    def validate_config(cls):
        """验证配置参数"""
        errors = []
        
        # 必需参数检查
        if not cls.CLOUDFLARE_EMAIL or cls.CLOUDFLARE_EMAIL == 'your-email@example.com':
            errors.append("请设置有效的Cloudflare邮箱地址")
        
        if not cls.CLOUDFLARE_API_KEY or cls.CLOUDFLARE_API_KEY == 'your-global-api-key-here':
            errors.append("请设置有效的Cloudflare API密钥")
        
        if not cls.CLOUDFLARE_ZONE_ID or cls.CLOUDFLARE_ZONE_ID == 'your-zone-id-here':
            errors.append("请设置有效的Zone ID")
        
        # 时间格式检查
        try:
            datetime.strptime(cls.LOCAL_START_TIME, "%Y-%m-%d %H:%M:%S")
            datetime.strptime(cls.LOCAL_END_TIME, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            errors.append("时间格式错误，请使用 'YYYY-MM-DD HH:MM:SS' 格式")
        
        if errors:
            print("❌ 配置验证失败：")
            for error in errors:
                print(f"   - {error}")
            print("\n💡 解决方案：")
            print("1. 直接修改Config类中的参数")
            print("2. 使用环境变量（推荐）：")
            print("   export CF_EMAIL='your-email@example.com'")
            print("   export CF_API_KEY='your-api-key'")
            print("   export CF_ZONE_ID='your-zone-id'")
            return False
        
        return True

# ================================
# 工具函数
# ================================

def to_utc_plus_8(utc_time_str):
    """将UTC时间字符串转换为UTC+8时间字符串"""
    utc_time = datetime.strptime(utc_time_str, "%Y-%m-%dT%H:%M:%SZ")
    utc_plus_8_time = utc_time.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=8)))
    return utc_plus_8_time.strftime("%Y-%m-%d %H:%M:%S")

def local_to_utc(local_time_str, format_str="%Y-%m-%d %H:%M:%S"):
    """将本地UTC+8时间转换为UTC时间字符串"""
    local_time = datetime.strptime(local_time_str, format_str)
    local_time = local_time.replace(tzinfo=timezone(timedelta(hours=8)))
    utc_time = local_time.astimezone(timezone.utc)
    return utc_time.strftime("%Y-%m-%dT%H:%M:%SZ")

# ================================
# 主采集器类
# ================================

class CloudflareCollector:
    """
    Cloudflare防火墙事件采集器
    
    功能：
    - 支持大时间跨度的数据采集
    - 自动优化查询窗口
    - 支持多种筛选条件
    - 智能处理Excel行数限制
    """
    
    def __init__(self):
        self.config = Config()
        
        # 从环境变量加载配置
        self.config.load_from_env()
        
        # 验证配置
        if not self.config.validate_config():
            sys.exit(1)
        
        self.safe_limit = int(self.config.API_LIMIT * self.config.API_SAFE_THRESHOLD)
        
        # 创建目录
        Path(self.config.OUTPUT_DIR).mkdir(exist_ok=True)
        Path(self.config.LOG_DIR).mkdir(exist_ok=True)
        
        # 设置日志
        self.setup_logging()
        
        # API配置
        self.url = "https://api.cloudflare.com/client/v4/graphql"
        self.headers = {
            'X-Auth-Email': self.config.CLOUDFLARE_EMAIL,
            'X-Auth-Key': self.config.CLOUDFLARE_API_KEY,
            'Content-Type': 'application/json'
        }
        
        # 缓存和计数器
        self.hour_cache = {}
        self.total_requests = 0
        self.total_records = 0
        self.failed_hours = 0
        self.cache_hits = 0
        
        self._print_config_summary()
    
    def _print_config_summary(self):
        """打印配置摘要"""
        print(f"✅ 初始化完成")
        print(f"📧 账户邮箱: {self.config.CLOUDFLARE_EMAIL}")
        print(f"🆔 Zone ID: {self.config.CLOUDFLARE_ZONE_ID}")
        print(f"⏰ 时间范围: {self.config.LOCAL_START_TIME} 至 {self.config.LOCAL_END_TIME}")
        print(f"🌐 目标主机: {self.config.TARGET_HOST or '全部主机'}")
        
        # 规则ID筛选
        if self.config.ENABLE_RULE_ID_FILTER and self.config.TARGET_RULE_ID:
            print(f"📋 规则ID筛选: 启用 - {self.config.TARGET_RULE_ID[:16]}...")
        else:
            print(f"📋 规则ID筛选: 禁用")
        
        # 地区筛选配置显示
        if self.config.ENABLE_COUNTRY_FILTER and self.config.FILTER_COUNTRIES:
            countries_str = ", ".join(self.config.FILTER_COUNTRIES)
            print(f"🌍 地区筛选: 启用 - [{countries_str}]")
        else:
            print(f"🌍 地区筛选: 禁用")
        
        # 其他筛选条件
        if self.config.FILTER_ACTIONS:
            actions_str = ", ".join(self.config.FILTER_ACTIONS)
            print(f"⚡ 动作筛选: [{actions_str}]")
        
        if self.config.EXCLUDE_ALLOW_ACTIONS:
            print(f"🚫 排除允许动作: 是")
    
    def setup_logging(self):
        """设置日志系统"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = Path(self.config.LOG_DIR) / f"cf_collector_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def build_api_filter(self, start_time, end_time):
        """构建API级筛选条件"""
        filter_dict = {
            "datetime_geq": start_time,
            "datetime_leq": end_time
        }
        
        # 规则ID筛选
        if self.config.ENABLE_RULE_ID_FILTER and self.config.TARGET_RULE_ID:
            filter_dict["ruleId"] = self.config.TARGET_RULE_ID
            print(f"    🎯 API筛选规则ID: {self.config.TARGET_RULE_ID[:16]}...")
        
        # 地区筛选
        if self.config.ENABLE_COUNTRY_FILTER and self.config.FILTER_COUNTRIES:
            if len(self.config.FILTER_COUNTRIES) == 1:
                filter_dict["clientCountryName"] = self.config.FILTER_COUNTRIES[0]
                print(f"    🌍 API筛选地区: {self.config.FILTER_COUNTRIES[0]}")
            else:
                filter_dict["clientCountryName_in"] = self.config.FILTER_COUNTRIES
                countries_str = ", ".join(self.config.FILTER_COUNTRIES)
                print(f"    🌍 API筛选地区: [{countries_str}]")
        
        # 动作筛选
        if self.config.FILTER_ACTIONS:
            if len(self.config.FILTER_ACTIONS) == 1:
                filter_dict["action"] = self.config.FILTER_ACTIONS[0]
            else:
                filter_dict["action_in"] = self.config.FILTER_ACTIONS
        
        # 排除允许动作
        if self.config.EXCLUDE_ALLOW_ACTIONS:
            filter_dict["action_neq"] = "allow"
        
        return filter_dict
    
    def get_firewall_events_for_window(self, start_time, end_time):
        """获取特定时间段的Cloudflare防火墙事件"""
        
        # GraphQL查询
        query = """
        query ListFirewallEvents($zoneTag: String!, $filter: FirewallEventsAdaptiveFilter_InputObject) {
          viewer {
            zones(filter: { zoneTag: $zoneTag }) {
              firewallEventsAdaptive(
                filter: $filter
                limit: 5000
                orderBy: [datetime_DESC]
              ) {
                action
                clientAsn
                clientCountryName
                clientIP
                clientRequestPath
                clientRequestQuery
                clientRequestHTTPHost
                datetime
                source
                userAgent
                rayName
                edgeResponseStatus
                originResponseStatus
              }
            }
          }
        }
        """
        
        # 构建筛选条件
        filter_dict = self.build_api_filter(start_time, end_time)
        
        variables = {
            "zoneTag": self.config.CLOUDFLARE_ZONE_ID,
            "filter": filter_dict
        }
        
        # 带重试的请求
        for attempt in range(self.config.REQUEST_RETRY_COUNT):
            try:
                self.total_requests += 1
                
                data = {"query": query, "variables": variables}
                
                response = requests.post(self.url, headers=self.headers, json=data)
                
                if response.status_code == 429:
                    print(f"⚠️ 达到API速率限制，等待{self.config.REQUEST_RETRY_DELAY}秒后重试...")
                    time.sleep(self.config.REQUEST_RETRY_DELAY)
                    continue
                
                if response.status_code != 200:
                    print(f"❌ HTTP错误: {response.status_code} - {response.text}")
                    time.sleep(self.config.REQUEST_RETRY_DELAY)
                    continue
                
                try:
                    results = response.json()
                except Exception as e:
                    print(f"❌ JSON解析错误: {str(e)}")
                    continue
                
                if results.get('errors'):
                    print(f"❌ API错误 (尝试 {attempt+1}/{self.config.REQUEST_RETRY_COUNT}): {results['errors']}")
                    
                    # 检查是否是字段错误
                    for error in results['errors']:
                        error_msg = error.get('message', '')
                        if 'ruleId' in error_msg or 'unknown field' in error_msg:
                            print(f"❌ API字段不被支持，可能不支持规则ID或地区筛选")
                            print(f"💡 建议：禁用相关筛选或检查API文档")
                            return [], 0, False
                    continue
                
                # 解析响应数据
                if (results.get('data') and 
                    results['data'].get('viewer') and 
                    results['data']['viewer'].get('zones') and 
                    len(results['data']['viewer']['zones']) > 0 and
                    results['data']['viewer']['zones'][0].get('firewallEventsAdaptive')):
                    
                    events = results['data']['viewer']['zones'][0]['firewallEventsAdaptive']
                    count = len(events)
                    is_truncated = count == self.config.API_LIMIT
                    
                    if count > 0:
                        print(f"    ✅ 成功获取 {count} 条匹配记录")
                    else:
                        print(f"    ⚪ 该时间段无匹配记录")
                    
                    return events, count, is_truncated
                else:
                    print(f"    ⚪ API返回空数据")
                    return [], 0, False
                    
            except requests.exceptions.Timeout:
                print(f"⏰ 请求超时 (尝试 {attempt+1}/{self.config.REQUEST_RETRY_COUNT})")
            except requests.exceptions.RequestException as e:
                print(f"🌐 请求异常: {str(e)} (尝试 {attempt+1}/{self.config.REQUEST_RETRY_COUNT})")
            except Exception as e:
                print(f"❌ 未知异常: {str(e)} (尝试 {attempt+1}/{self.config.REQUEST_RETRY_COUNT})")
                
            if attempt < self.config.REQUEST_RETRY_COUNT - 1:
                time.sleep(self.config.REQUEST_RETRY_DELAY)
        
        print(f"❌ 在{self.config.REQUEST_RETRY_COUNT}次尝试后仍未获取到数据")
        return [], 0, False
    
    def binary_search_optimal_window_seconds(self, hour_start_str):
        """在单个小时内使用二分法寻找最优窗口"""
        hour_start_dt = datetime.strptime(hour_start_str, "%Y-%m-%dT%H:%M:%SZ")
        
        # 小时结束时间不能超过全局结束时间
        hour_end_dt = min(hour_start_dt + timedelta(hours=1), self.utc_end_dt)
        hour_end_str = hour_end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # 生成缓存键
        filter_key_parts = []
        if self.config.TARGET_RULE_ID:
            filter_key_parts.append(self.config.TARGET_RULE_ID[:8])
        if self.config.ENABLE_COUNTRY_FILTER and self.config.FILTER_COUNTRIES:
            filter_key_parts.extend(self.config.FILTER_COUNTRIES)
        
        cache_key = f"{hour_start_dt.strftime('%Y%m%d_%H')}_{'_'.join(filter_key_parts)}"
        
        if cache_key in self.hour_cache:
            self.cache_hits += 1
            return self.hour_cache[cache_key]
        
        # 先测试整个小时
        print(f"  🔍 测试整小时: {hour_start_dt.strftime('%Y-%m-%d %H')}时")
        events, count, is_truncated = self.get_firewall_events_for_window(hour_start_str, hour_end_str)
        
        if not is_truncated:
            windows = [{
                'start': hour_start_str,
                'end': hour_end_str,
                'seconds': 3600
            }]
            self.hour_cache[cache_key] = windows
            
            if count > 0:
                print(f"  ✅ 整小时优化成功: {count} 条匹配记录")
            
            return windows
        
        # 需要进行分割
        print(f"  ⚡ 小时内数据截断，开始分割优化...")
        
        windows = []
        current_dt = hour_start_dt
        
        while current_dt < hour_end_dt:
            remaining_seconds = (hour_end_dt - current_dt).total_seconds()
            
            # 二分法寻找最优窗口
            optimal_seconds = self.find_optimal_seconds(
                current_dt, 
                min(remaining_seconds, self.config.MAX_WINDOW_SECONDS)
            )
            
            window_end_dt = current_dt + timedelta(seconds=optimal_seconds)
            if window_end_dt > hour_end_dt:
                window_end_dt = hour_end_dt
            
            windows.append({
                'start': current_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                'end': window_end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                'seconds': optimal_seconds
            })
            
            current_dt = window_end_dt
            time.sleep(self.config.REQUEST_DELAY)
        
        self.hour_cache[cache_key] = windows
        print(f"  ✅ 分割优化完成: {len(windows)} 个窗口")
        
        return windows
    
    def find_optimal_seconds(self, start_dt, max_seconds):
        """二分法寻找最优窗口"""
        left = self.config.MIN_WINDOW_SECONDS
        right = max_seconds
        optimal_seconds = self.config.MIN_WINDOW_SECONDS
        
        for iteration in range(self.config.BINARY_SEARCH_MAX_ITERATIONS):
            if right - left <= self.config.BINARY_SEARCH_PRECISION_SECONDS:
                break
                
            mid_seconds = (left + right) / 2
            test_end_dt = start_dt + timedelta(seconds=mid_seconds)
            
            test_start = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            test_end = test_end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            _, count, is_truncated = self.get_firewall_events_for_window(test_start, test_end)
            
            if is_truncated:
                right = mid_seconds - self.config.BINARY_SEARCH_PRECISION_SECONDS
            else:
                optimal_seconds = mid_seconds
                left = mid_seconds + self.config.BINARY_SEARCH_PRECISION_SECONDS
        
        return optimal_seconds
    
    def split_time_range_by_hour(self, start_time, end_time):
        """将时间范围分割成小时区间"""
        start_dt = datetime.strptime(start_time, "%Y-%m-%dT%H:%M:%SZ")
        end_dt = datetime.strptime(end_time, "%Y-%m-%dT%H:%M:%SZ")
        
        time_ranges = []
        current = start_dt.replace(minute=0, second=0, microsecond=0)
        
        while current < end_dt:
            next_time = current + timedelta(hours=1)
            if next_time > end_dt:
                next_time = end_dt
                
            time_ranges.append(current.strftime("%Y-%m-%dT%H:%M:%SZ"))
            current = next_time
        
        return time_ranges
    
    def process_single_hour(self, hour_start):
        """处理单个小时的数据采集"""
        try:
            local_time = to_utc_plus_8(hour_start)
            thread_name = threading.current_thread().name
            
            print(f"[{thread_name}] 🕐 开始处理: {local_time[:13]}时")
            
            # 获取该小时的优化窗口
            windows = self.binary_search_optimal_window_seconds(hour_start)
            
            # 收集所有窗口数据
            hour_events = []
            
            for window in windows:
                events, count, is_truncated = self.get_firewall_events_for_window(
                    window['start'], window['end']
                )
                
                if events:
                    hour_events.extend(events)
                    
                    if is_truncated:
                        print(f"[{thread_name}] ⚠️ 窗口截断: {count} 条记录")
                
                time.sleep(self.config.REQUEST_DELAY)
            
            self.total_records += len(hour_events)
            
            if len(hour_events) > 0:
                print(f"[{thread_name}] ✅ 完成 {local_time[:13]}时：{len(hour_events)} 条匹配记录，{len(windows)} 个窗口")
            else:
                print(f"[{thread_name}] ⚪ 完成 {local_time[:13]}时：无匹配记录，{len(windows)} 个窗口")
            
            return hour_events
            
        except Exception as e:
            print(f"[{thread_name}] ❌ 处理小时失败 {hour_start}: {str(e)}")
            self.failed_hours += 1
            return []
    
    def collect_data(self):
        """主数据采集函数"""
        print("\n=== 🚀 开始数据采集 ===")
        
        # 时间转换
        utc_start_time = local_to_utc(self.config.LOCAL_START_TIME)
        utc_end_time = local_to_utc(self.config.LOCAL_END_TIME)
        
        print(f"📅 本地时间范围: {self.config.LOCAL_START_TIME} 至 {self.config.LOCAL_END_TIME}")
        print(f"🌍 UTC时间范围: {utc_start_time} 至 {utc_end_time}")
        
        # 记录UTC时间范围
        self.utc_start_dt = datetime.strptime(utc_start_time, "%Y-%m-%dT%H:%M:%SZ")
        self.utc_end_dt = datetime.strptime(utc_end_time, "%Y-%m-%dT%H:%M:%SZ")
        
        # 获取分割后的时间区间
        hour_ranges = self.split_time_range_by_hour(utc_start_time, utc_end_time)
        total_hours = len(hour_ranges)
        
        print(f"📊 将查询分为 {total_hours} 个小时区间")
        
        # 采集数据
        all_events = []
        
        if self.config.ENABLE_PARALLEL and total_hours > 1:
            # 并行处理
            print(f"⚡ 并行处理模式，最大并发: {self.config.MAX_CONCURRENT_HOURS}")
            
            with ThreadPoolExecutor(max_workers=self.config.MAX_CONCURRENT_HOURS) as executor:
                future_to_hour = {
                    executor.submit(self.process_single_hour, hour): hour
                    for hour in hour_ranges
                }
                
                completed = 0
                for future in as_completed(future_to_hour):
                    completed += 1
                    hour_events = future.result()
                    all_events.extend(hour_events)
                    
                    # 进度显示
                    if completed % 10 == 0 or completed == total_hours:
                        print(f"📈 进度更新: 已处理 {completed}/{total_hours} 个小时，累计 {len(all_events)} 条匹配记录")
        else:
            # 串行处理
            print("⚡ 串行处理模式")
            
            for i, hour in enumerate(hour_ranges):
                hour_start = datetime.strptime(hour, "%Y-%m-%dT%H:%M:%SZ")
                
                print(f"[{i+1}/{total_hours}] 🕐 获取 {hour_start.strftime('%Y-%m-%d %H')}时 的数据...")
                
                hour_events = self.process_single_hour(hour)
                all_events.extend(hour_events)
                
                # 每10个小时显示进度
                if (i + 1) % 10 == 0 or i == len(hour_ranges) - 1:
                    print(f"📈 进度更新: 已处理 {i+1}/{total_hours} 个小时，累计 {len(all_events)} 条匹配记录")
        
        return all_events
    
    def save_to_excel(self, all_events):
        """保存数据到文件"""
        if not all_events:
            print("⚠️ 未获取到任何匹配的数据")
            print("💡 可能的原因:")
            print("   1. 指定时间范围内没有触发相关事件")
            print("   2. 筛选条件过于严格")
            print("   3. API权限不足")
            print("   4. Zone ID不正确")
            return ""
        
        # 转换为DataFrame
        df = pd.DataFrame(all_events)
        print(f"\n=== 📋 数据获取完成 ===")
        print(f"📊 获取到的匹配记录数: {len(df):,}")
        
        # 添加本地时间列
        df['local_datetime'] = df['datetime'].apply(to_utc_plus_8)
        
        # 主机筛选
        filtered_df = df
        if self.config.TARGET_HOST:
            print(f"\n=== 🎯 主机筛选 ===")
            
            contains_target_host = df['clientRequestHTTPHost'].str.contains(self.config.TARGET_HOST, na=False)
            count_with_target_host = contains_target_host.sum()
            print(f"📍 主机名包含'{self.config.TARGET_HOST}'的记录数: {count_with_target_host:,}")
            
            filtered_df = df[contains_target_host]
            
            print(f"\n=== 📋 最终筛选结果 ===")
            print(f"📊 API筛选匹配记录数: {len(df):,}")
            print(f"🎯 主机筛选后记录数: {len(filtered_df):,}")
        
        # 生成文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename_parts = ["CF_WAF_Events"]
        
        if self.config.TARGET_HOST:
            safe_host = self.config.TARGET_HOST.replace('.', '_')
            filename_parts.append(safe_host)
        
        if self.config.ENABLE_RULE_ID_FILTER and self.config.TARGET_RULE_ID:
            rule_id_short = self.config.TARGET_RULE_ID[:8]
            filename_parts.append(f"Rule_{rule_id_short}")
        
        if self.config.ENABLE_COUNTRY_FILTER and self.config.FILTER_COUNTRIES:
            countries_suffix = "_".join(self.config.FILTER_COUNTRIES)
            filename_parts.append(f"Countries_{countries_suffix}")
        
        filename_parts.append(timestamp)
        base_filename = "_".join(filename_parts)
        
        # Excel行数限制
        EXCEL_MAX_ROWS = 1048576
        
        # 保存数据
        if len(filtered_df) > 0:
            print(f"\n=== 💾 保存数据 ===")
            
            if len(filtered_df) < EXCEL_MAX_ROWS:
                # 保存为Excel
                filepath = Path(self.config.OUTPUT_DIR) / f"{base_filename}.xlsx"
                filtered_df.to_excel(filepath, index=False, engine='openpyxl')
                print(f"✅ 数据已保存为Excel: {filepath.name}")
                print(f"📁 共 {len(filtered_df):,} 条记录")
            else:
                # 保存为CSV
                filepath = Path(self.config.OUTPUT_DIR) / f"{base_filename}.csv"
                filtered_df.to_csv(filepath, index=False, encoding='utf-8-sig')
                print(f"✅ 数据量超出Excel限制，已保存为CSV: {filepath.name}")
                print(f"📁 共 {len(filtered_df):,} 条记录")
            
            return str(filepath)
        else:
            print(f"⚠️ 经过筛选后没有匹配记录")
            return ""
    
    def run(self):
        """运行完整采集流程"""
        start_time = datetime.now()
        
        try:
            # 数据采集
            all_events = self.collect_data()
            
            # 保存数据
            filepath = self.save_to_excel(all_events)
            
            # 输出统计信息
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            print(f"\n=== 🎉 数据采集完成 ===")
            print(f"📡 API请求数: {self.total_requests}")
            print(f"📊 匹配记录数: {self.total_records}")
            print(f"❌ 失败小时数: {self.failed_hours}")
            print(f"💾 缓存命中数: {self.cache_hits}")
            print(f"⏱️ 总耗时: {duration:.1f} 秒")
            
            if self.total_requests > 0:
                efficiency = self.total_records / self.total_requests
                print(f"⚡ 平均效率: {efficiency:.1f} 条/请求")
            
            if filepath:
                print(f"📁 输出文件: {filepath}")
            
            return filepath
            
        except KeyboardInterrupt:
            print("\n⏹️ 用户中断")
            return ""
        except Exception as e:
            print(f"\n💥 程序错误: {str(e)}")
            return ""

# ================================
# 主程序入口
# ================================

def print_usage_guide():
    """打印使用指南"""
    print("""
🛡️ Cloudflare WAF事件采集器使用指南

📋 配置方式（二选一）：

方式1: 直接修改代码中的Config类
   - 编辑Config类中的参数
   - 适合一次性使用或测试

方式2: 使用环境变量（推荐）
   export CF_EMAIL='your-email@example.com'
   export CF_API_KEY='your-api-key'
   export CF_ZONE_ID='your-zone-id'
   export CF_TARGET_HOST='example.com'
   export CF_RULE_ID='rule-id-here'
   export CF_COUNTRIES='CN,HK,TW'
   export CF_ENABLE_RULE_FILTER='true'
   export CF_ENABLE_COUNTRY_FILTER='true'

🔑 获取API凭证：
   1. 登录Cloudflare Dashboard
   2. 进入 My Profile -> API Tokens
   3. 使用Global API Key或创建自定义Token

📊 Zone ID获取：
   1. 进入目标域名的Dashboard
   2. 右侧Overview页面可找到Zone ID

⚠️ 注意事项：
   - 首次使用建议小范围测试
   - 大时间跨度查询可能耗时较长
   - 请确保API密钥有足够权限
   - 建议使用环境变量保护敏感信息

📖 更多信息：
   项目地址: https://github.com/BlueSkyXN/Comprehensive-Network-Defense
""")

def main():
    """主程序"""
    print("🛡️ Cloudflare WAF事件采集器 - 通用版本")
    print("📝 作者: BlueSkyXN")
    print("🔗 项目地址: https://github.com/BlueSkyXN/Comprehensive-Network-Defense")
    print("=" * 70)
    
    # 检查是否需要显示帮助
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        print_usage_guide()
        return
    
    # 创建采集器并运行
    try:
        collector = CloudflareCollector()
        result_file = collector.run()
        
        if result_file:
            print(f"\n🎉 数据采集完成!")
            print(f"📁 文件路径: {result_file}")
            
            # 根据文件类型给出使用建议
            if result_file.endswith('.csv'):
                print(f"\n💡 CSV文件使用建议:")
                print("1. 可以直接用Excel打开查看")
                print("2. 如需高级分析，建议导入数据库")
                print("3. 支持所有行数，无Excel限制")
            else:
                print(f"\n💡 Excel文件已就绪，可直接打开使用")
        else:
            print("\n❌ 采集失败或无数据")
            print("\n💡 troubleshooting建议:")
            print("1. 检查API凭证是否正确")
            print("2. 确认Zone ID是否有效")
            print("3. 验证时间范围内是否有相关事件")
            print("4. 检查筛选条件是否过于严格")
            print("5. 确认API权限是否足够")
            
    except KeyboardInterrupt:
        print("\n⏹️ 用户中断")
    except Exception as e:
        print(f"\n💥 程序异常: {str(e)}")
        print("\n💡 如需帮助，请运行: python script.py --help")

if __name__ == "__main__":
    main()