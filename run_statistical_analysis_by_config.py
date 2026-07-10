#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分配置统计分析脚本
按message_count和payload_size分组进行统计检验
"""

import csv
import numpy as np
from scipy import stats
from collections import defaultdict
import os

def load_baseline_data(csv_file):
    """加载baseline对比数据"""
    results = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append({
                'protocol': row['protocol'],
                'attack_type': row['attack_type'],
                'message_count': int(row['message_count']),
                'payload_size': int(row['payload_size']),
                'success_rate': float(row['success_rate']),
                'throughput': float(row['throughput_msg_per_sec']),
                'rtt_mean': float(row['rtt_mean_ms']),
            })
    return results

def analyze_by_configuration(results):
    """按配置分组分析"""
    # 按(message_count, payload_size)分组
    configs = defaultdict(lambda: defaultdict(list))
    
    for r in results:
        if r['attack_type'] == 'none':  # 只分析正常通信
            key = (r['message_count'], r['payload_size'])
            configs[key][r['protocol']].append(r['throughput'])
    
    return configs

def run_anova_by_config(configs):
    """对每个配置进行单因素方差分析"""
    print("=" * 80)
    print("分配置统计分析（正常通信吞吐量）")
    print("=" * 80)
    
    for config, protocols in sorted(configs.items()):
        msg_count, payload_size = config
        print(f"\n配置: message_count={msg_count}, payload_size={payload_size}")
        print("-" * 60)
        
        # 收集各协议的数据
        protocol_names = []
        protocol_data = []
        
        for protocol, throughputs in sorted(protocols.items()):
            protocol_names.append(protocol)
            protocol_data.append(throughputs)
            print(f"  {protocol}: n={len(throughputs)}, mean={np.mean(throughputs):.0f}, std={np.std(throughputs):.0f}")
        
        # 进行单因素方差分析
        if len(protocol_data) >= 2 and all(len(d) >= 2 for d in protocol_data):
            f_stat, p_value = stats.f_oneway(*protocol_data)
            
            # 计算效应量 (eta-squared)
            all_data = np.concatenate(protocol_data)
            grand_mean = np.mean(all_data)
            ss_between = sum(len(d) * (np.mean(d) - grand_mean)**2 for d in protocol_data)
            ss_total = np.sum((all_data - grand_mean)**2)
            eta_squared = ss_between / ss_total if ss_total > 0 else 0
            
            print(f"\n  ANOVA结果:")
            print(f"    F-statistic = {f_stat:.4f}")
            print(f"    p-value = {p_value:.6f}")
            print(f"    η² = {eta_squared:.4f}")
            
            if p_value < 0.001:
                print(f"    结论: p < 0.001, 差异极显著 (***)")
            elif p_value < 0.01:
                print(f"    结论: p < 0.01, 差异非常显著 (**)")
            elif p_value < 0.05:
                print(f"    结论: p < 0.05, 差异显著 (*)")
            else:
                print(f"    结论: p >= 0.05, 差异不显著 (ns)")
            
            # 进行事后检验（Tukey HSD的简化版本：两两t检验）
            print(f"\n  事后检验（两两t检验）:")
            for i in range(len(protocol_names)):
                for j in range(i+1, len(protocol_names)):
                    t_stat, t_p = stats.ttest_ind(protocol_data[i], protocol_data[j])
                    
                    # 计算Cohen's d
                    pooled_std = np.sqrt((np.var(protocol_data[i]) + np.var(protocol_data[j])) / 2)
                    cohens_d = abs(np.mean(protocol_data[i]) - np.mean(protocol_data[j])) / pooled_std if pooled_std > 0 else 0
                    
                    significance = "***" if t_p < 0.001 else "**" if t_p < 0.01 else "*" if t_p < 0.05 else "ns"
                    
                    print(f"    {protocol_names[i]} vs {protocol_names[j]}: t={t_stat:.3f}, p={t_p:.6f} {significance}, d={cohens_d:.2f}")

def analyze_attack_detection_by_config(results):
    """按配置分析攻击检测率"""
    print("\n" + "=" * 80)
    print("分配置统计分析（攻击检测率）")
    print("=" * 80)
    
    # 按(message_count, payload_size, attack_type)分组
    configs = defaultdict(lambda: defaultdict(list))
    
    for r in results:
        if r['attack_type'] != 'none':  # 只分析攻击场景
            key = (r['message_count'], r['payload_size'], r['attack_type'])
            configs[key][r['protocol']].append(r['success_rate'])
    
    for config, protocols in sorted(configs.items()):
        msg_count, payload_size, attack_type = config
        print(f"\n配置: message_count={msg_count}, payload_size={payload_size}, attack_type={attack_type}")
        print("-" * 60)
        
        for protocol, success_rates in sorted(protocols.items()):
            detection_rate = (1 - np.mean(success_rates) / 100) * 100  # 转换为检测率
            print(f"  {protocol}: n={len(success_rates)}, 检测率={detection_rate:.1f}%")

def generate_summary_table(configs):
    """生成汇总表格"""
    print("\n" + "=" * 80)
    print("汇总表格（按配置）")
    print("=" * 80)
    
    # 按协议汇总
    protocol_summary = defaultdict(lambda: {'throughputs': [], 'rtts': []})
    
    for config, protocols in configs.items():
        for protocol, throughputs in protocols.items():
            protocol_summary[protocol]['throughputs'].extend(throughputs)
    
    print(f"\n{'协议':<15} {'配置数':<10} {'总样本数':<10} {'平均吞吐量':<15} {'标准差':<15} {'95% CI':<20}")
    print("-" * 85)
    
    for protocol, data in sorted(protocol_summary.items()):
        throughputs = data['throughputs']
        n = len(throughputs)
        mean = np.mean(throughputs)
        std = np.std(throughputs)
        ci95 = stats.t.interval(0.95, df=n-1, loc=mean, scale=stats.sem(throughputs))
        
        print(f"{protocol:<15} {len(configs):<10} {n:<10} {mean:<15.0f} {std:<15.0f} [{ci95[0]:.0f}, {ci95[1]:.0f}]")

def main():
    csv_file = "results/real_baseline_comparison/real_baseline_comparison_results.csv"
    
    if not os.path.exists(csv_file):
        print(f"错误: 找不到文件 {csv_file}")
        return
    
    print("加载数据...")
    results = load_baseline_data(csv_file)
    print(f"加载了 {len(results)} 条记录")
    
    # 按配置分组
    configs = analyze_by_configuration(results)
    
    # 运行ANOVA分析
    run_anova_by_config(configs)
    
    # 分析攻击检测率
    analyze_attack_detection_by_config(results)
    
    # 生成汇总表格
    generate_summary_table(configs)

if __name__ == "__main__":
    main()
