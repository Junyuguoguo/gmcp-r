# -*- coding: utf-8 -*-
# gmcp/config.py

import os

# =========================
# Network config
# =========================

# server.py / real_server.py 绑定地址
# 本机测试：127.0.0.1
# 云服务器公网监听：0.0.0.0
SERVER_BIND_HOST = os.getenv("GMCP_BIND_HOST", "127.0.0.1")

# client.py / real_network_client 连接目标
# 本机测试：127.0.0.1
# Mac -> 云服务器：服务器公网 IP
SERVER_TARGET_HOST = os.getenv("GMCP_TARGET_HOST", "127.0.0.1")

DEFAULT_HOST = os.getenv("GMCP_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.getenv("GMCP_PORT", "9000"))

# =========================
# GMCP basic config
# =========================

SESSION_ID = "session-001"
CLIENT_ID = "client-001"
SERVER_ID = "server-001"
EPOCH = 1

# 实验用共享密钥
# 原型系统中使用 HMAC-SHA256 模拟认证标签
SHARED_KEY = b"gmcp-demo-shared-key"

# 每隔多少条消息生成检查点
CHECKPOINT_INTERVAL = 100

# socket 缓冲区
BUFFER_SIZE = 65535

# 默认发送消息数量
DEFAULT_MESSAGE_COUNT = 1000