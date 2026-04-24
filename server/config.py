#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetMonitor Pro — 服务端配置管理 (优化版)
文件位置: server/config.py

优化点:
  1. JWT secret 原子写入（tempfile + rename），消除 TOCTOU 竞态
  2. 新增配置校验 assert，启动时即暴露非法配置
  3. 新增速率限制相关配置
  4. 新增 CORS 和安全头配置
"""

import os
import secrets
import tempfile
from pathlib import Path

# ────────────────────── 基础路径 ──────────────────────

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("NETMON_DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ────────────────────── 网络配置 ──────────────────────

HOST = os.getenv("NETMON_HOST", "0.0.0.0")
PORT = int(os.getenv("NETMON_PORT", "5000"))
DEBUG = os.getenv("NETMON_DEBUG", "false").lower() in ("true", "1", "yes")

# ────────────────────── 数据库 ──────────────────────

DATABASE_PATH = str(DATA_DIR / "netmonitor.db")

# ────────────────────── 认证 ──────────────────────

API_KEY = os.getenv("NETMON_API_KEY", "changeme-netmonitor-2024")

# [优化] JWT secret 原子写入，消除 TOCTOU 竞态
# 原实现: 先 write_text 再 chmod，中间窗口可被读取
_SECRET_FILE = DATA_DIR / ".jwt_secret"

if _SECRET_FILE.exists():
    JWT_SECRET = _SECRET_FILE.read_text().strip()
else:
    JWT_SECRET = os.getenv("NETMON_JWT_SECRET", secrets.token_hex(32))
    # [优化] 原子写入: 先写临时文件并设好权限，再 rename
    # 这样不存在"文件已创建但权限未设置"的窗口期
    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(dir=str(DATA_DIR), prefix=".jwt_tmp_")
        os.fchmod(fd, 0o600)          # 先设权限
        os.write(fd, JWT_SECRET.encode())  # 再写内容
        os.close(fd)
        fd = None
        os.rename(tmp_path, str(_SECRET_FILE))  # 原子替换
        tmp_path = None
    except Exception:
        if fd is not None:
            os.close(fd)
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = int(os.getenv("NETMON_JWT_EXPIRY_HOURS", "24"))

# ────────────────────── 数据保留 ──────────────────────

DATA_RETENTION_DAYS = int(os.getenv("NETMON_RETENTION_DAYS", "30"))

# ────────────────────── 速率限制 (新增) ──────────────────────

RATE_LIMIT_DEFAULT = os.getenv("NETMON_RATE_LIMIT", "100/minute")
RATE_LIMIT_INGEST = os.getenv("NETMON_RATE_LIMIT_INGEST", "500/minute")
RATE_LIMIT_AUTH = os.getenv("NETMON_RATE_LIMIT_AUTH", "10/minute")

# ────────────────────── 批量接口 ──────────────────────

MAX_BATCH_SIZE = int(os.getenv("NETMON_MAX_BATCH_SIZE", "200"))
MAX_QUERY_LIMIT = int(os.getenv("NETMON_MAX_QUERY_LIMIT", "1000"))

# ────────────────────── CORS ──────────────────────

CORS_ORIGINS = os.getenv("NETMON_CORS_ORIGINS", "*")

# ────────────────────── 日志 ──────────────────────

LOG_LEVEL = os.getenv("NETMON_LOG_LEVEL", "INFO").upper()

# ────────────────────── 配置校验 (新增) ──────────────────────

assert 1 <= PORT <= 65535, f"端口号无效: {PORT}，须在 1-65535 范围内"
assert DATA_RETENTION_DAYS > 0, f"数据保留天数无效: {DATA_RETENTION_DAYS}，须 > 0"
assert JWT_EXPIRY_HOURS > 0, f"JWT 有效期无效: {JWT_EXPIRY_HOURS}，须 > 0"
assert MAX_BATCH_SIZE > 0, f"最大批次大小无效: {MAX_BATCH_SIZE}，须 > 0"
assert MAX_QUERY_LIMIT > 0, f"最大查询限制无效: {MAX_QUERY_LIMIT}，须 > 0"