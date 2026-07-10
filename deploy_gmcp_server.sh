#!/bin/bash
# deploy_gmcp_server.sh
#
# 部署GMCP-R服务器到远程服务器

set -e

# 配置
REMOTE_HOST="38.76.169.74"
REMOTE_USER="root"
REMOTE_PASSWORD="123456"
REMOTE_DIR="/www/wwwroot/gmcp-r"
LOCAL_DIR="/Users/a0000/Desktop/实验/gmcp_r"

echo "=========================================="
echo "GMCP-R Server Deployment"
echo "=========================================="

# 1. 创建远程目录
echo "[1/6] Creating remote directory..."
sshpass -p "${REMOTE_PASSWORD}" ssh -o StrictHostKeyChecking=no "${REMOTE_USER}@${REMOTE_HOST}" "
    mkdir -p ${REMOTE_DIR}
    mkdir -p ${REMOTE_DIR}/gmcp
    mkdir -p ${REMOTE_DIR}/results
    mkdir -p ${REMOTE_DIR}/checkpoints
"

# 2. 同步gmcp模块
echo "[2/6] Syncing gmcp module..."
sshpass -p "${REMOTE_PASSWORD}" rsync -avz --delete \
    -e "ssh -o StrictHostKeyChecking=no" \
    "${LOCAL_DIR}/gmcp/" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/gmcp/"

# 3. 同步服务器脚本
echo "[3/6] Syncing server scripts..."
sshpass -p "${REMOTE_PASSWORD}" rsync -avz \
    -e "ssh -o StrictHostKeyChecking=no" \
    "${LOCAL_DIR}/real_tcp_server.py" \
    "${LOCAL_DIR}/real_tcp_server_with_ticket.py" \
    "${LOCAL_DIR}/server.py" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"

# 4. 同步实验脚本（客户端运行）
echo "[4/6] Syncing experiment scripts..."
sshpass -p "${REMOTE_PASSWORD}" rsync -avz \
    -e "ssh -o StrictHostKeyChecking=no" \
    "${LOCAL_DIR}/run_real_ticket_recovery_experiment.py" \
    "${LOCAL_DIR}/run_checkpoint_recovery_experiment.py" \
    "${LOCAL_DIR}/run_tc_netem_experiment.py" \
    "${LOCAL_DIR}/run_real_network_experiment.py" \
    "${LOCAL_DIR}/run_real_recovery_experiment.py" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"

# 5. 同步绘图脚本
echo "[5/6] Syncing plot scripts..."
sshpass -p "${REMOTE_PASSWORD}" rsync -avz \
    -e "ssh -o StrictHostKeyChecking=no" \
    "${LOCAL_DIR}/plot_ticket_recovery_results.py" \
    "${LOCAL_DIR}/plot_checkpoint_recovery_results.py" \
    "${LOCAL_DIR}/plot_tc_netem_results.py" \
    "${LOCAL_DIR}/plot_real_network_results.py" \
    "${LOCAL_DIR}/plot_real_recovery_results.py" \
    "${LOCAL_DIR}/plot_real_memory_results.py" \
    "${LOCAL_DIR}/plot_baseline_comparison_results.py" \
    "${LOCAL_DIR}/generate_comprehensive_report.py" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"

# 6. 同步配置文件
echo "[6/6] Syncing config files..."
sshpass -p "${REMOTE_PASSWORD}" rsync -avz \
    -e "ssh -o StrictHostKeyChecking=no" \
    "${LOCAL_DIR}/requirements.txt" \
    "${LOCAL_DIR}/README.md" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/" 2>/dev/null || true

echo ""
echo "=========================================="
echo "Deployment Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. SSH to server: ssh ${REMOTE_USER}@${REMOTE_HOST}"
echo "2. Install dependencies: cd ${REMOTE_DIR} && pip install -r requirements.txt"
echo "3. Start server: python3 real_tcp_server_with_ticket.py"
echo "4. Run experiments from local machine"
echo ""
echo "Server directory: ${REMOTE_DIR}"
