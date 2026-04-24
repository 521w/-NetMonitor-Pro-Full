#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetMonitor Pro — Flask REST API 服务端 (优化版)
文件位置: server/app.py

优化点:
  1. [致命修复] _insert_event 双重白名单 + 参数化查询，消除 SQL 注入
  2. [致命修复] 全局速率限制 (flask-limiter)，防暴力刷/DoS
  3. [高危修复] export 端点改为流式 generator 响应，防 OOM
  4. [高危修复] 所有请求参数安全转换，非法值不再 500
  5. [高危修复] cleanup 新增 admin 角色校验
  6. [中危修复] PRAGMA 只在首次连接执行一次
  7. [中危修复] cleanup 合并为单一事务
  8. [中危修复] stats 端点 group_by 白名单强化
  9. [改进] 生产环境强制要求修改默认 API_KEY
  10. [改进] 统一错误处理和响应格式
"""

import json
import logging
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import Flask, Response, g, jsonify, request

from config import (
    API_KEY,
    CORS_ORIGINS,
    DATA_RETENTION_DAYS,
    DATABASE_PATH,
    DEBUG,
    HOST,
    JWT_ALGORITHM,
    JWT_EXPIRY_HOURS,
    JWT_SECRET,
    LOG_LEVEL,
    MAX_BATCH_SIZE,
    MAX_QUERY_LIMIT,
    PORT,
    RATE_LIMIT_AUTH,
    RATE_LIMIT_DEFAULT,
    RATE_LIMIT_INGEST,
)

# ────────────────────── 可选依赖 ──────────────────────

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    HAS_LIMITER = True
except ImportError:
    HAS_LIMITER = False

# ────────────────────── 日志 ──────────────────────

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netmon.server")

# ────────────────────── Flask App ──────────────────────

app = Flask(__name__)
app.config["JSON_AS_ASCII"] = False

# [致命修复] 速率限制
if HAS_LIMITER:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=[RATE_LIMIT_DEFAULT],
        storage_uri="memory://",
    )
    log.info("速率限制已启用: 默认=%s", RATE_LIMIT_DEFAULT)
else:
    limiter = None
    log.warning("⚠️ flask-limiter 未安装，速率限制已禁用！"
                " pip install flask-limiter")

# ────────────────────── 数据库 ──────────────────────

# [优化] PRAGMA 只在首次连接执行，不再每次请求都跑
_pragma_initialized = set()

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT,
    event_type    TEXT,
    pid           INTEGER,
    tgid          INTEGER,
    uid           INTEGER,
    gid           INTEGER,
    comm          TEXT,
    ip_version    INTEGER,
    protocol      TEXT,
    src_addr      TEXT,
    src_port      INTEGER,
    dst_addr      TEXT,
    dst_port      INTEGER,
    bytes_sent    INTEGER DEFAULT 0,
    connect_result INTEGER,
    device_id     TEXT,
    extra         TEXT,
    received_at   TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_dst_addr ON events(dst_addr);
CREATE INDEX IF NOT EXISTS idx_events_dst_port ON events(dst_port);
CREATE INDEX IF NOT EXISTS idx_events_device_id ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_received ON events(received_at);

CREATE TABLE IF NOT EXISTS api_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token      TEXT UNIQUE NOT NULL,
    name       TEXT,
    role       TEXT DEFAULT 'user',
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT
);
"""


def get_db() -> sqlite3.Connection:
    """获取数据库连接（带 PRAGMA 单次初始化优化）"""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row

        # [优化] PRAGMA 只在该数据库文件首次连接时执行
        if DATABASE_PATH not in _pragma_initialized:
            g.db.execute("PRAGMA journal_mode=WAL")
            g.db.execute("PRAGMA synchronous=NORMAL")
            g.db.execute("PRAGMA busy_timeout=5000")
            g.db.execute("PRAGMA cache_size=-64000")   # 64 MiB
            _pragma_initialized.add(DATABASE_PATH)

    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """初始化数据库表结构"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.executescript(SCHEMA_SQL)
    conn.close()
    log.info("数据库已初始化: %s", DATABASE_PATH)


# ────────────────────── 认证 ──────────────────────

def require_auth(f):
    """JWT / Bearer token 认证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "缺少认证令牌"}), 401

        token = auth_header[7:]

        # 先尝试 JWT 验证
        try:
            payload = jwt.decode(token, JWT_SECRET,
                                 algorithms=[JWT_ALGORITHM])
            g.auth_user = payload.get("sub", "unknown")
            g.auth_role = payload.get("role", "user")
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "令牌已过期"}), 401
        except jwt.InvalidTokenError:
            pass

        # 再检查数据库中的 API token
        db = get_db()
        row = db.execute(
            "SELECT name, role, expires_at FROM api_tokens WHERE token = ?",
            (token,)
        ).fetchone()

        if row is None:
            return jsonify({"error": "无效的认证令牌"}), 401

        if row["expires_at"]:
            exp = datetime.fromisoformat(row["expires_at"])
            if exp < datetime.now(timezone.utc):
                return jsonify({"error": "令牌已过期"}), 401

        g.auth_user = row["name"] or "api_token"
        g.auth_role = row["role"] or "user"
        return f(*args, **kwargs)

    return decorated


def require_admin(f):
    """[新增] Admin 角色校验装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if getattr(g, "auth_role", "user") != "admin":
            return jsonify({"error": "需要管理员权限"}), 403
        return f(*args, **kwargs)
    return decorated


# ────────────────────── 安全工具函数 ──────────────────────

def safe_int(key: str, default=None, min_val=None, max_val=None):
    """[新增] 安全整数参数解析，非法值不再 500"""
    val = request.args.get(key)
    if val is None:
        return default
    try:
        result = int(val)
        if min_val is not None:
            result = max(result, min_val)
        if max_val is not None:
            result = min(result, max_val)
        return result
    except (ValueError, TypeError):
        return default


def safe_str(key: str, default=None, max_len=200):
    """[新增] 安全字符串参数解析"""
    val = request.args.get(key)
    if val is None:
        return default
    return str(val)[:max_len]


# ────────────────────── 事件插入 ──────────────────────

# [致命修复] 列名硬编码白名单——不可被用户输入扩展
ALLOWED_EVENT_COLUMNS = frozenset({
    "timestamp", "event_type", "pid", "tgid", "uid", "gid",
    "comm", "ip_version", "protocol", "src_addr", "src_port",
    "dst_addr", "dst_port", "bytes_sent", "connect_result",
    "device_id", "extra",
})


def validate_event(evt: dict) -> dict:
    """校验并过滤事件字段"""
    return {k: v for k, v in evt.items() if k in ALLOWED_EVENT_COLUMNS}


def _insert_event(db: sqlite3.Connection, evt: dict):
    """
    [致命修复] 安全插入事件记录。

    原实现: f-string 直接拼列名进 SQL，虽有白名单但脆弱。
    修复:   双重保险——
      1. 列名来自 ALLOWED_EVENT_COLUMNS 冻结集合（不可扩展）
      2. 值使用参数化占位符
    """
    safe_evt = validate_event(evt)
    if not safe_evt:
        return

    columns = list(safe_evt.keys())
    placeholders = ", ".join(["?"] * len(columns))
    # 列名来自白名单硬编码集合，不可通过用户输入注入
    col_names = ", ".join(columns)
    values = [safe_evt[c] for c in columns]

    db.execute(
        f"INSERT INTO events ({col_names}) VALUES ({placeholders})",
        values,
    )


# ────────────────────── API 端点: 认证 ──────────────────────

@app.route("/api/v1/auth/token", methods=["POST"])
def create_token():
    """通过 API_KEY 获取 JWT token"""
    if limiter:
        limiter.limit(RATE_LIMIT_AUTH)(lambda: None)()

    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key", "")
    name = data.get("name", "anonymous")

    if api_key != API_KEY:
        return jsonify({"error": "API Key 无效"}), 401

    now = datetime.now(timezone.utc)
    payload = {
        "sub": name,
        "role": "user",
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRY_HOURS),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return jsonify({
        "token": token,
        "expires_in": JWT_EXPIRY_HOURS * 3600,
        "token_type": "Bearer",
    })


# ────────────────────── API 端点: 数据接入 ──────────────────────

@app.route("/api/v1/ingest", methods=["POST"])
@require_auth
def ingest_event():
    """接收单条事件"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "请求体为空或非 JSON"}), 400

    db = get_db()
    try:
        _insert_event(db, data)
        db.commit()
        return jsonify({"status": "ok", "inserted": 1})
    except Exception as e:
        log.error("插入事件失败: %s", e)
        return jsonify({"error": "插入失败"}), 500


@app.route("/api/v1/ingest/batch", methods=["POST"])
@require_auth
def ingest_batch():
    """批量接收事件"""
    data = request.get_json(silent=True)
    if not data or "events" not in data:
        return jsonify({"error": "缺少 events 字段"}), 400

    events = data["events"]
    if not isinstance(events, list):
        return jsonify({"error": "events 须为数组"}), 400

    if len(events) > MAX_BATCH_SIZE:
        return jsonify({
            "error": f"批次过大，最多 {MAX_BATCH_SIZE} 条"
        }), 400

    db = get_db()
    inserted = 0
    errors = []

    for i, evt in enumerate(events):
        try:
            _insert_event(db, evt)
            inserted += 1
        except Exception as e:
            errors.append({"index": i, "error": str(e)})

    db.commit()

    status_code = 200 if not errors else 207
    return jsonify({
        "status": "ok" if not errors else "partial",
        "inserted": inserted,
        "errors": errors,
        "total": len(events),
    }), status_code


# ────────────────────── API 端点: 查询 ──────────────────────

@app.route("/api/v1/events", methods=["GET"])
@require_auth
def query_events():
    """查询事件列表（带过滤和分页）"""
    db = get_db()
    conditions = []
    params = []

    # 事件类型过滤
    event_type = safe_str("event_type")
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)

    # 目标地址过滤
    dst_addr = safe_str("dst_addr")
    if dst_addr:
        conditions.append("dst_addr = ?")
        params.append(dst_addr)

    # [高危修复] 目标端口——安全整数转换，非法值不再 500
    dst_port = safe_int("dst_port")
    if dst_port is not None:
        conditions.append("dst_port = ?")
        params.append(dst_port)

    # 源地址过滤
    src_addr = safe_str("src_addr")
    if src_addr:
        conditions.append("src_addr = ?")
        params.append(src_addr)

    # PID 过滤
    pid = safe_int("pid")
    if pid is not None:
        conditions.append("pid = ?")
        params.append(pid)

    # UID 过滤
    uid = safe_int("uid")
    if uid is not None:
        conditions.append("uid = ?")
        params.append(uid)

    # 进程名过滤
    comm = safe_str("comm")
    if comm:
        conditions.append("comm = ?")
        params.append(comm)

    # 设备 ID 过滤
    device_id = safe_str("device_id")
    if device_id:
        conditions.append("device_id = ?")
        params.append(device_id)

    # 时间范围过滤
    start_time = safe_str("start")
    if start_time:
        conditions.append("timestamp >= ?")
        params.append(start_time)

    end_time = safe_str("end")
    if end_time:
        conditions.append("timestamp <= ?")
        params.append(end_time)

    # 构建 WHERE 子句
    where = " AND ".join(conditions) if conditions else "1=1"

    # 分页（带上限保护）
    limit = safe_int("limit", default=100, min_val=1, max_val=MAX_QUERY_LIMIT)
    offset = safe_int("offset", default=0, min_val=0)

    # 排序
    ALLOWED_ORDER_BY = {"id", "timestamp", "event_type", "pid",
                        "dst_addr", "dst_port", "received_at"}
    order_by = safe_str("order_by", default="id")
    if order_by not in ALLOWED_ORDER_BY:
        order_by = "id"

    order_dir = safe_str("order", default="DESC").upper()
    if order_dir not in ("ASC", "DESC"):
        order_dir = "DESC"

    sql = (f"SELECT * FROM events WHERE {where} "
           f"ORDER BY {order_by} {order_dir} "
           f"LIMIT ? OFFSET ?")
    params.extend([limit, offset])

    rows = db.execute(sql, params).fetchall()

    # 总数查询
    count_row = db.execute(
        f"SELECT COUNT(*) as cnt FROM events WHERE {where}",
        params[:-2],  # 去掉 limit/offset
    ).fetchone()
    total = count_row["cnt"] if count_row else 0

    return jsonify({
        "events": [dict(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


# ────────────────────── API 端点: 统计 ──────────────────────

# [中危修复] group_by 白名单硬编码，强化防护
ALLOWED_GROUP_BY = frozenset({
    "event_type", "protocol", "dst_addr", "dst_port",
    "src_addr", "comm", "uid", "pid", "device_id", "ip_version",
})


@app.route("/api/v1/stats", methods=["GET"])
@require_auth
def stats():
    """统计查询"""
    db = get_db()

    group_by = safe_str("group_by", default="event_type")
    if group_by not in ALLOWED_GROUP_BY:
        return jsonify({
            "error": f"不支持的分组字段: {group_by}",
            "allowed": sorted(ALLOWED_GROUP_BY),
        }), 400

    top_n = safe_int("top", default=20, min_val=1, max_val=100)

    # 时间范围
    conditions = []
    params = []

    start_time = safe_str("start")
    if start_time:
        conditions.append("timestamp >= ?")
        params.append(start_time)

    end_time = safe_str("end")
    if end_time:
        conditions.append("timestamp <= ?")
        params.append(end_time)

    where = " AND ".join(conditions) if conditions else "1=1"

    sql = (f"SELECT {group_by} as label, COUNT(*) as count "
           f"FROM events WHERE {where} "
           f"GROUP BY {group_by} "
           f"ORDER BY count DESC LIMIT ?")
    params.append(top_n)

    rows = db.execute(sql, params).fetchall()

    # 总事件数
    total_row = db.execute(
        f"SELECT COUNT(*) as cnt FROM events WHERE {where}",
        params[:-1],
    ).fetchone()

    return jsonify({
        "group_by": group_by,
        "stats": [{"label": r["label"], "count": r["count"]} for r in rows],
        "total_events": total_row["cnt"] if total_row else 0,
    })


# ────────────────────── API 端点: 导出 ──────────────────────

@app.route("/api/v1/export", methods=["GET"])
@require_auth
def export_events():
    """
    [高危修复] 流式导出事件——逐行生成 JSONL，不再全量加载到内存。

    原实现: fetchall() 全部加载，数据量大时 OOM 崩溃。
    修复:   使用 generator + fetchone 逐行流式输出。
    """
    db = get_db()
    conditions = []
    params = []

    # 复用查询过滤逻辑
    event_type = safe_str("event_type")
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)

    device_id = safe_str("device_id")
    if device_id:
        conditions.append("device_id = ?")
        params.append(device_id)

    start_time = safe_str("start")
    if start_time:
        conditions.append("timestamp >= ?")
        params.append(start_time)

    end_time = safe_str("end")
    if end_time:
        conditions.append("timestamp <= ?")
        params.append(end_time)

    where = " AND ".join(conditions) if conditions else "1=1"

    def generate():
        """逐行生成 JSONL 流"""
        cursor = db.execute(
            f"SELECT * FROM events WHERE {where} ORDER BY id ASC",
            params,
        )
        while True:
            row = cursor.fetchone()
            if row is None:
                break
            yield json.dumps(dict(row), ensure_ascii=False) + "\n"

    return Response(
        generate(),
        mimetype="application/x-ndjson",
        headers={
            "Content-Disposition": "attachment; filename=netmon_export.jsonl",
            "X-Content-Type-Options": "nosniff",
        },
    )


# ────────────────────── API 端点: 管理 ──────────────────────

@app.route("/api/v1/admin/cleanup", methods=["POST"])
@require_auth
@require_admin  # [高危修复] 只有 admin 角色可执行清理
def cleanup():
    """
    清理过期数据。
    [中危修复] 合并为单一事务，不再两次 commit。
    [高危修复] 新增 admin 角色校验。
    """
    db = get_db()
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=DATA_RETENTION_DAYS)).isoformat()
    now_iso = now.isoformat()

    cursor_events = db.execute(
        "DELETE FROM events WHERE received_at < ?", (cutoff,)
    )
    cursor_tokens = db.execute(
        "DELETE FROM api_tokens WHERE expires_at < ?", (now_iso,)
    )

    # [中危修复] 一次提交，一个事务
    db.commit()

    return jsonify({
        "status": "ok",
        "events_deleted": cursor_events.rowcount,
        "tokens_deleted": cursor_tokens.rowcount,
        "retention_days": DATA_RETENTION_DAYS,
        "cutoff_time": cutoff,
    })


@app.route("/api/v1/admin/db-stats", methods=["GET"])
@require_auth
@require_admin
def db_stats():
    """数据库统计信息"""
    db = get_db()
    event_count = db.execute("SELECT COUNT(*) as cnt FROM events").fetchone()
    token_count = db.execute("SELECT COUNT(*) as cnt FROM api_tokens").fetchone()

    # 获取数据库文件大小
    try:
        db_size = os.path.getsize(DATABASE_PATH)
    except OSError:
        db_size = 0

    return jsonify({
        "event_count": event_count["cnt"] if event_count else 0,
        "token_count": token_count["cnt"] if token_count else 0,
        "database_size_bytes": db_size,
        "database_size_mb": round(db_size / (1024 * 1024), 2),
        "retention_days": DATA_RETENTION_DAYS,
    })


# ────────────────────── 健康检查 ──────────────────────

@app.route("/health", methods=["GET"])
def health():
    """健康检查端点（无需认证）"""
    try:
        db = get_db()
        db.execute("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False

    status = "ok" if db_ok else "degraded"
    return jsonify({
        "status": status,
        "database": "ok" if db_ok else "error",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }), 200 if db_ok else 503


# ────────────────────── 错误处理 ──────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "端点不存在"}), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "不支持的 HTTP 方法"}), 405


@app.errorhandler(500)
def internal_error(e):
    log.error("内部错误: %s", e)
    return jsonify({"error": "服务器内部错误"}), 500


if HAS_LIMITER:
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({
            "error": "请求过于频繁，请稍后再试",
            "retry_after": e.description,
        }), 429


# ────────────────────── CORS ──────────────────────

@app.after_request
def add_security_headers(response):
    """添加安全响应头"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"

    if CORS_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = CORS_ORIGINS
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization"
        )
        response.headers["Access-Control-Allow-Methods"] = (
            "GET, POST, OPTIONS"
        )
    return response


# ────────────────────── 启动入口 ──────────────────────

def main():
    """应用启动入口"""
    init_db()

    # [改进] 生产环境强制要求修改默认 API_KEY
    if API_KEY == "changeme-netmonitor-2024":
        if not DEBUG:
            log.critical(
                "❌ 生产环境必须设置 NETMON_API_KEY 环境变量！"
                "当前使用默认值，存在严重安全风险。"
            )
            sys.exit(1)
        else:
            log.warning("⚠️ 使用默认 API_KEY，仅限开发环境！")

    log.info("NetMonitor Pro Server 启动中...")
    log.info("  地址: %s:%d", HOST, PORT)
    log.info("  调试: %s", DEBUG)
    log.info("  数据库: %s", DATABASE_PATH)
    log.info("  数据保留: %d 天", DATA_RETENTION_DAYS)
    log.info("  速率限制: %s", "已启用" if HAS_LIMITER else "已禁用")

    app.run(host=HOST, port=PORT, debug=DEBUG)


if __name__ == "__main__":
    main()