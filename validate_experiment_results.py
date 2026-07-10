#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GMCP-R 实验结果验证脚本
验证所有实验数据的一致性和正确性
"""

import csv
import os
import sys
from collections import defaultdict


def as_bool(value):
    """Return True for CSV truthy values."""
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


def read_csv_rows(filepath):
    with open(filepath, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def check_file_exists(filepath, min_rows=0):
    """检查文件是否存在且行数满足要求"""
    if not os.path.exists(filepath):
        return False, f"文件不存在: {filepath}"
    
    rows = read_csv_rows(filepath)
    
    if len(rows) < min_rows:
        return False, f"行数不足: {len(rows)} < {min_rows}"
    
    return True, f"OK ({len(rows)}行)"


def check_memory_ticket_recovery():
    """检查MemoryTicket恢复实验"""
    filepath = 'paper_data/06_memory_ticket_recovery.csv'
    if not os.path.exists(filepath):
        return [f"❌ {filepath}: 文件不存在"]
    
    rows = read_csv_rows(filepath)
    
    results = []
    n = len(rows)
    
    # 核心指标
    checks = [
        ('recovery_success', lambda r: as_bool(r['recovery_success'])),
        ('memory_match_after_recovery', lambda r: as_bool(r['memory_match_after_recovery'])),
        ('ticket_verified', lambda r: as_bool(r.get('ticket_verified'))),
        ('submitted_ticket_present', lambda r: as_bool(r.get('submitted_ticket_present'))),
        ('server_ticket_verified', lambda r: as_bool(r.get('server_ticket_verified'))),
        ('response_state_match', lambda r: as_bool(r.get('response_state_match'))),
    ]
    
    for name, check_fn in checks:
        count = sum(1 for r in rows if check_fn(r))
        if count == n:
            results.append(f"✅ {name}: {count}/{n}")
        else:
            results.append(f"❌ {name}: {count}/{n}")
    
    # 按攻击类型检查
    attack_stats = defaultdict(lambda: {'total': 0, 'success': 0})
    for r in rows:
        attack = r['attack_type']
        attack_stats[attack]['total'] += 1
        if as_bool(r['recovery_success']):
            attack_stats[attack]['success'] += 1
    
    for attack, data in sorted(attack_stats.items()):
        rate = data['success'] / data['total'] * 100
        if rate == 100:
            results.append(f"✅ {attack}: {rate:.0f}%")
        else:
            results.append(f"❌ {attack}: {rate:.0f}%")
    
    return results


def check_checkpoint_recovery():
    """检查Checkpoint恢复实验"""
    filepath = 'paper_data/07_checkpoint_recovery.csv'
    if not os.path.exists(filepath):
        return [f"❌ {filepath}: 文件不存在"]
    
    rows = read_csv_rows(filepath)
    
    results = []
    n = len(rows)
    
    # reconstruction_match
    match_count = sum(1 for r in rows if as_bool(r['reconstruction_match']))
    results.append(f"{'✅' if match_count == n else '❌'} reconstruction_match: {match_count}/{n}")
    
    # reconstructed_mem == target_mem
    field_match = sum(1 for r in rows if r['reconstructed_mem'] == r['target_mem'])
    results.append(f"{'✅' if field_match == n else '❌'} reconstructed_mem == target_mem: {field_match}/{n}")
    
    # replay_count一致性
    replay_ok = sum(1 for r in rows if int(r['replay_count']) == int(r['target_seq']) - int(r['checkpoint_seq']))
    results.append(f"{'✅' if replay_ok == n else '❌'} replay_count一致性: {replay_ok}/{n}")
    
    # checkpoint_seq < target_seq
    ckpt_ok = sum(1 for r in rows if int(r['checkpoint_seq']) < int(r['target_seq']))
    results.append(f"{'✅' if ckpt_ok == n else '❌'} checkpoint_seq < target_seq: {ckpt_ok}/{n}")
    
    # replay_count < checkpoint_interval
    replay_bound = sum(1 for r in rows if int(r['replay_count']) < int(r['checkpoint_interval']))
    results.append(f"{'✅' if replay_bound == n else '❌'} replay_count < k: {replay_bound}/{n}")
    
    return results


def check_ticket_attacks():
    """检查票据攻击实验"""
    filepath = 'paper_data/02_ticket_attacks.csv'
    if not os.path.exists(filepath):
        return [f"❌ {filepath}: 文件不存在"]
    
    rows = read_csv_rows(filepath)
    
    results = []
    n = len(rows)
    
    # 拒绝率
    reject = sum(1 for r in rows if r['recovery_success'] == 'False')
    results.append(f"{'✅' if reject == n else '❌'} 票据拒绝率: {reject}/{n}")
    
    # 按类型
    attack_reject = defaultdict(lambda: {'total': 0, 'reject': 0})
    for r in rows:
        a = r['attack_type']
        attack_reject[a]['total'] += 1
        if r['recovery_success'] == 'False':
            attack_reject[a]['reject'] += 1
    
    for attack, data in sorted(attack_reject.items()):
        rate = data['reject'] / data['total'] * 100
        results.append(f"{'✅' if rate == 100 else '❌'} {attack}: {rate:.0f}%")
    
    return results


def check_baseline():
    """检查Baseline对比实验"""
    filepath = 'paper_data/01_real_baseline.csv'
    if not os.path.exists(filepath):
        return [f"❌ {filepath}: 文件不存在"]
    
    rows = read_csv_rows(filepath)
    
    results = []
    
    attack_detect = calculate_baseline_detection_rates(rows)
    
    for p, data in sorted(attack_detect.items()):
        rate = data['detected'] / data['total'] * 100 if data['total'] > 0 else 0
        results.append(f"{'✅' if rate >= 50 else '❌'} {p}: 检测率={rate:.0f}%")
    
    return results


def calculate_baseline_detection_rates(rows):
    """Calculate attack detection from the server-side audit field.

    Do not infer detection from success_rate: timeouts or transport errors can
    also lower success_rate without proving the server detected the attack.
    """
    attack_detect = defaultdict(lambda: {'total': 0, 'detected': 0})
    for r in rows:
        if r['attack_type'] != 'none':
            p = r['protocol']
            attack_detect[p]['total'] += 1
            if as_bool(r.get('attack_detected_by_server')):
                attack_detect[p]['detected'] += 1
    return attack_detect


def check_real_recovery_summary():
    """Check recovery summary is regenerated from the raw recovery CSV."""
    raw_path = 'paper_data/06_memory_ticket_recovery.csv'
    summary_path = 'results/real_recovery/summary_real_recovery.csv'
    if not os.path.exists(raw_path) or not os.path.exists(summary_path):
        return [f"❌ recovery summary inputs missing: {raw_path}, {summary_path}"]

    raw_rows = read_csv_rows(raw_path)
    summary_rows = {r['attack_type']: r for r in read_csv_rows(summary_path)}
    grouped = defaultdict(list)
    for row in raw_rows:
        grouped[row['attack_type']].append(row)

    results = []
    for attack_type, rows in sorted(grouped.items()):
        summary = summary_rows.get(attack_type)
        if summary is None:
            results.append(f"❌ {attack_type}: summary row missing")
            continue
        latencies = [float(r['recovery_latency_ms']) for r in rows]
        expected_mean = round(sum(latencies) / len(latencies), 3)
        file_mean = round(float(summary['latency_mean_ms']), 3)
        if int(summary['sample_count']) != len(rows):
            results.append(f"❌ {attack_type}: sample_count mismatch")
        elif file_mean != expected_mean:
            results.append(f"❌ {attack_type}: latency_mean_ms {file_mean} != {expected_mean}")
        else:
            results.append(f"✅ {attack_type}: summary matches raw")
    return results


def main():
    print("=" * 80)
    print("GMCP-R 实验结果验证")
    print("=" * 80)
    
    all_passed = True
    
    # 1. 文件完整性
    print("\n[1] 文件完整性检查")
    print("-" * 40)
    
    files = {
        'paper_data/01_real_baseline.csv': 300,
        'paper_data/02_ticket_attacks.csv': 200,
        'paper_data/03_performance.csv': 100,
        'paper_data/04_concurrency.csv': 10,
        'paper_data/05_weak_network.csv': 100,
        'paper_data/06_memory_ticket_recovery.csv': 800,
        'paper_data/07_checkpoint_recovery.csv': 100,
    }
    
    total_rows = 0
    for filepath, min_rows in files.items():
        ok, msg = check_file_exists(filepath, min_rows)
        print(f"{'✅' if ok else '❌'} {filepath}: {msg}")
        if not ok:
            all_passed = False
        if ok and os.path.exists(filepath):
            with open(filepath, 'r') as f:
                total_rows += len(list(csv.DictReader(f)))
    
    print(f"\n总数据量: {total_rows}行")
    
    # 2. MemoryTicket恢复
    print("\n[2] MemoryTicket恢复实验")
    print("-" * 40)
    
    results = check_memory_ticket_recovery()
    for r in results:
        print(r)
        if r.startswith('❌'):
            all_passed = False
    
    # 3. Checkpoint恢复
    print("\n[3] Checkpoint恢复实验")
    print("-" * 40)
    
    results = check_checkpoint_recovery()
    for r in results:
        print(r)
        if r.startswith('❌'):
            all_passed = False
    
    # 4. 票据攻击
    print("\n[4] 票据攻击实验")
    print("-" * 40)
    
    results = check_ticket_attacks()
    for r in results:
        print(r)
        if r.startswith('❌'):
            all_passed = False
    
    # 5. Baseline对比
    print("\n[5] Baseline对比实验")
    print("-" * 40)
    
    results = check_baseline()
    for r in results:
        print(r)
        if r.startswith('❌'):
            all_passed = False

    # 6. 真实恢复summary一致性
    print("\n[6] 真实恢复summary一致性")
    print("-" * 40)

    results = check_real_recovery_summary()
    for r in results:
        print(r)
        if r.startswith('❌'):
            all_passed = False
    
    # 总结
    print("\n" + "=" * 80)
    if all_passed:
        print("✅ 所有检查通过！")
        sys.exit(0)
    else:
        print("❌ 存在失败项，请检查")
        sys.exit(1)
    print("=" * 80)


if __name__ == "__main__":
    main()
