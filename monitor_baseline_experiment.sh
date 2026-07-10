#!/bin/bash
# monitor_baseline_experiment.sh
# 监控baseline对比实验进度

LOG_FILE="/tmp/baseline_experiment.log"
CSV_FILE="/Users/a0000/Desktop/实验/gmcp_r/results/real_baseline_comparison/real_baseline_comparison_results.csv"

echo "=========================================="
echo "Baseline Experiment Monitor"
echo "=========================================="
echo ""

# 检查进程是否运行
if pgrep -f "run_real_baseline_comparison.py" > /dev/null; then
    echo "✅ Experiment is RUNNING"
else
    echo "❌ Experiment is NOT running"
fi

echo ""

# 检查日志文件
if [ -f "$LOG_FILE" ]; then
    echo "📊 Progress:"
    tail -5 "$LOG_FILE" | grep -E "^\[" | tail -1
    echo ""
    
    # 统计已完成的实验数
    COMPLETED=$(grep -c "✅\|❌" "$LOG_FILE" 2>/dev/null || echo "0")
    echo "Completed: $COMPLETED / 3600 experiments"
    
    # 计算完成百分比
    if [ "$COMPLETED" -gt 0 ]; then
        PERCENTAGE=$(echo "scale=1; $COMPLETED * 100 / 3600" | bc)
        echo "Progress: ${PERCENTAGE}%"
    fi
else
    echo "⏳ Waiting for log file..."
fi

echo ""

# 检查CSV文件
if [ -f "$CSV_FILE" ]; then
    ROWS=$(wc -l < "$CSV_FILE")
    echo "📝 CSV rows: $ROWS"
else
    echo "📝 CSV file not yet created"
fi

echo ""
echo "=========================================="
echo "Commands:"
echo "  View log: tail -f $LOG_FILE"
echo "  Check progress: watch -n 10 $0"
echo "=========================================="
