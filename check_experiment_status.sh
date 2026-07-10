#!/bin/bash
# check_experiment_status.sh
# 检查所有实验状态

echo "=========================================="
echo "GMCP-R 实验状态检查"
echo "=========================================="
echo ""

# 检查服务器
echo "🖥️ 服务器状态:"
if lsof -i :9001 > /dev/null 2>&1; then
    echo "  ✅ Baseline服务器 (端口9001) 运行中"
else
    echo "  ❌ Baseline服务器 (端口9001) 未运行"
fi

if lsof -i :9000 > /dev/null 2>&1; then
    echo "  ✅ GMCP-R服务器 (端口9000) 运行中"
else
    echo "  ❌ GMCP-R服务器 (端口9000) 未运行"
fi

echo ""
echo "📊 实验数据:"

# Baseline对比
if [ -f "results/real_baseline_comparison/real_baseline_comparison_results.csv" ]; then
    ROWS=$(wc -l < "results/real_baseline_comparison/real_baseline_comparison_results.csv")
    echo "  ✅ Baseline对比: $((ROWS-1)) 行数据"
else
    echo "  ❌ Baseline对比: 无数据"
fi

# 性能基准
if [ -f "results/performance/performance_benchmark_results.csv" ]; then
    ROWS=$(wc -l < "results/performance/performance_benchmark_results.csv")
    echo "  ✅ 性能基准: $((ROWS-1)) 行数据"
else
    echo "  ❌ 性能基准: 无数据"
fi

# 并发测试
if [ -f "results/concurrent/concurrent_results.csv" ]; then
    ROWS=$(wc -l < "results/concurrent/concurrent_results.csv")
    echo "  ✅ 并发测试: $((ROWS-1)) 行数据"
else
    echo "  ❌ 并发测试: 无数据"
fi

# 弱网仿真
if [ -f "results/weak_network_simulation/weak_network_simulation_results.csv" ]; then
    ROWS=$(wc -l < "results/weak_network_simulation/weak_network_simulation_results.csv")
    echo "  ✅ 弱网仿真: $((ROWS-1)) 行数据"
else
    echo "  ⏳ 弱网仿真: 进行中"
fi

echo ""
echo "📁 图表文件:"

# 检查图表
for dir in results/*/figures; do
    if [ -d "$dir" ]; then
        COUNT=$(ls -1 "$dir"/*.png 2>/dev/null | wc -l)
        echo "  📊 $dir: $COUNT 个图表"
    fi
done

echo ""
echo "=========================================="
