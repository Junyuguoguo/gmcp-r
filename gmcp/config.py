# gmcp/config.py

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9000

SESSION_ID = "session-001"
CLIENT_ID = "client-001"
SERVER_ID = "server-001"

EPOCH = 1

# 实验用共享密钥
# 真实论文中可以说明：原型系统中使用 HMAC-SHA256 模拟认证标签
SHARED_KEY = b"gmcp-demo-shared-key"

# 每隔多少条消息生成检查点
CHECKPOINT_INTERVAL = 100

# socket 缓冲区
BUFFER_SIZE = 65535

# 默认发送消息数量
DEFAULT_MESSAGE_COUNT = 1000