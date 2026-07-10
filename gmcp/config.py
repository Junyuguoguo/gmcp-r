# -*- coding: utf-8 -*-
# gmcp/config.py
# -*- coding: utf-8 -*-
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
# 优先从环境变量读取，如果未设置则使用默认值
SHARED_KEY = os.getenv("GMCP_SHARED_KEY", "gmcp-demo-shared-key").encode("utf-8")

# 密钥分离（安全设计）
# DATA_AUTH_KEY: 客户端与服务器共享，用于DATA报文认证
DATA_AUTH_KEY = os.getenv("GMCP_DATA_AUTH_KEY", "gmcp-data-auth-key-2026").encode("utf-8")
# TICKET_AUTH_KEY: 仅服务器持有，用于MemoryTicket签发和验证
TICKET_AUTH_KEY = os.getenv("GMCP_TICKET_AUTH_KEY", "gmcp-ticket-auth-key-2026").encode("utf-8")
# CHECKPOINT_AUTH_KEY: 仅服务器持有，用于Checkpoint认证标签
CHECKPOINT_AUTH_KEY = os.getenv("GMCP_CHECKPOINT_AUTH_KEY", "gmcp-checkpoint-auth-key-2026").encode("utf-8")

# 每隔多少条消息生成检查点
CHECKPOINT_INTERVAL = 100

# socket 缓冲区
BUFFER_SIZE = 65535

# 默认发送消息数量
DEFAULT_MESSAGE_COUNT = 1000

# =========================
# Security config
# =========================

# timestamp 时间窗口（秒）
# 拒绝时间戳偏差超过此值的包
TIMESTAMP_WINDOW_SECONDS = int(os.getenv("GMCP_TIMESTAMP_WINDOW", "300"))

# nonce 过期时间（秒）
NONCE_TTL_SECONDS = int(os.getenv("GMCP_NONCE_TTL", "3600"))

# MemoryTicket 默认 TTL（秒）
TICKET_TTL_SECONDS = int(os.getenv("GMCP_TICKET_TTL", "3600"))

# Session lock strategy: "per_session_lock" (default) or "global_lock"
LOCK_STRATEGY = os.getenv("GMCP_LOCK_STRATEGY", "per_session_lock")