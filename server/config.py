"""
NetMonitor Pro — 服务端配置
支持环境变量覆盖，开箱即用默认值
"""

import os
import secrets
from pathlib import Path

# ─── 基础路径 ───
BASE_DIR = Path(__file__).parent.resolve()
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

# ─── 数据库 ───
DATABASE_PATH = os.getenv("NETMON_DB_PATH", str(DATA_DIR / "netmonitor.db"))

# ─── JWT 认证 ───
# 首次运行自动生成密钥并写入 .secret 文件
_SECRET_FILE = DATA_DIR / ".jwt_secret"
if _SECRET_FILE.exists():
    JWT_SECRET = _SECRET_FILE.read_text().strip()
else:
    JWT_SECRET = os.getenv("NETMON_JWT_SECRET", secrets.token_hex(32))
    _SECRET_FILE.write_text(JWT_SECRET)
    os.chmod(_SECRET_FILE, 0o600)

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("NETMON_JWT_EXPIRY_HOURS", "72"))

# ─── API 密钥（用于获取 JWT Token 的认证）───
# 生产环境务必通过环境变量设置！
API_KEY = os.getenv("NETMON_API_KEY", "changeme-netmonitor-2024")

# ─── 服务器 ───
HOST = os.getenv("NETMON_HOST", "0.0.0.0")
PORT = int(os.getenv("NETMON_PORT", "5000"))
DEBUG = os.getenv("NETMON_DEBUG", "false").lower() == "true"

# ─── 批量写入 ───
MAX_BATCH_SIZE = int(os.getenv("NETMON_MAX_BATCH_SIZE", "500"))
MAX_SINGLE_PAYLOAD_KB = int(os.getenv("NETMON_MAX_PAYLOAD_KB", "512"))

# ─── 数据保留策略 ───
DATA_RETENTION_DAYS = int(os.getenv("NETMON_RETENTION_DAYS", "30"))

# ─── 日志 ───
LOG_LEVEL = os.getenv("NETMON_LOG_LEVEL", "INFO")
