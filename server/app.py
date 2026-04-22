"""
NetMonitor Pro — 云端 API 服务
功能：
  - SQLite 持久化存储（WAL 模式，高并发写入）
  - JWT Token 认证
  - JSON Schema 数据校验
  - 单条 / 批量事件写入
  - 多维度查询（时间、应用、IP、端口、协议）
  - 统计聚合接口
  - 数据保留策略自动清理
"""

import sqlite3
import logging
import time
import hashlib
import functools
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
from pathlib import Path

from flask import Flask, request, jsonify, g
import jwt

import config

# ─── 日志 ───
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("netmon-server")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = config.MAX_SINGLE_PAYLOAD_KB * 1024


# ══════════════════════════════════════════════════════════════════
#  数据库层
# ══════════════════════════════════════════════════════════════════

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    timestamp       TEXT,
    event_type      TEXT    NOT NULL,
    pid             INTEGER,
    tgid            INTEGER,
    uid             INTEGER,
    gid             INTEGER,
    comm            TEXT,
    ip_version      INTEGER,
    protocol        TEXT,
    src_addr        TEXT,
    src_port        INTEGER,
    dst_addr        TEXT,
    dst_port        INTEGER,
    bytes_sent      INTEGER DEFAULT 0,
    connect_result  TEXT,
    device_id       TEXT,
    extra           TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp   ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_event_type  ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_comm        ON events(comm);
CREATE INDEX IF NOT EXISTS idx_events_dst_addr    ON events(dst_addr);
CREATE INDEX IF NOT EXISTS idx_events_dst_port    ON events(dst_port);
CREATE INDEX IF NOT EXISTS idx_events_uid         ON events(uid);
CREATE INDEX IF NOT EXISTS idx_events_device_id   ON events(device_id);
CREATE INDEX IF NOT EXISTS idx_events_received    ON events(received_at);

CREATE TABLE IF NOT EXISTS api_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT    NOT NULL UNIQUE,
    device_id   TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at  TEXT    NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0
);
"""


def get_db() -> sqlite3.Connection:
    """获取当前请求的数据库连接（线程安全）"""
    if "db" not in g:
        g.db = sqlite3.connect(config.DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
        g.db.execute("PRAGMA busy_timeout=5000")
        g.db.execute("PRAGMA cache_size=-64000")  # 64MB
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """初始化数据库表结构"""
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.executescript(DB_SCHEMA)
    conn.close()
    log.info("数据库初始化完成: %s", config.DATABASE_PATH)


# ══════════════════════════════════════════════════════════════════
#  JWT 认证
# ══════════════════════════════════════════════════════════════════

def create_token(device_id: str = None) -> tuple:
    """生成 JWT Token，返回 (token_str, expires_at)"""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=config.JWT_EXPIRY_HOURS)
    payload = {
        "iat": now,
        "exp": expires,
        "sub": "netmon-client",
        "device_id": device_id,
    }
    token = jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)
    return token, expires.isoformat()


def verify_token(token: str) -> dict:
    """验证 JWT Token，返回 payload 或抛异常"""
    return jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])


def require_auth(f):
    """路由装饰器 — 强制 JWT 认证"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "缺少认证令牌", "code": "AUTH_MISSING"}), 401
        token = auth_header[7:]
        try:
            payload = verify_token(token)
            g.auth_payload = payload
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "令牌已过期", "code": "AUTH_EXPIRED"}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({"error": f"无效令牌: {e}", "code": "AUTH_INVALID"}), 401
        return f(*args, **kwargs)
    return decorated


# ══════════════════════════════════════════════════════════════════
#  数据校验
# ══════════════════════════════════════════════════════════════════

VALID_EVENT_TYPES = {
    "TCP_CONNECT", "TCP_CONNECT_RET", "UDP_SEND",
    "TCP_CLOSE", "DNS_QUERY",
}
VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "6", "17", "1"}

REQUIRED_FIELDS = {"event_type"}
OPTIONAL_FIELDS = {
    "timestamp", "pid", "tgid", "uid", "gid", "comm",
    "ip_version", "protocol", "src_addr", "src_port",
    "dst_addr", "dst_port", "bytes_sent", "connect_result",
    "device_id", "extra",
}
ALL_FIELDS = REQUIRED_FIELDS | OPTIONAL_FIELDS


def validate_event(data: dict) -> tuple:
    """校验单条事件，返回 (clean_data, error_msg)"""
    if not isinstance(data, dict):
        return None, "事件必须是 JSON 对象"

    # 必填字段检查
    for field in REQUIRED_FIELDS:
        if field not in data:
            return None, f"缺少必填字段: {field}"

    # 事件类型校验
    if data["event_type"] not in VALID_EVENT_TYPES:
        return None, f"无效事件类型: {data['event_type']}（允许: {VALID_EVENT_TYPES}）"

    # 协议校验（可选字段）
    if "protocol" in data and data["protocol"] not in VALID_PROTOCOLS:
        return None, f"无效协议: {data['protocol']}"

    # IP 版本校验
    if "ip_version" in data and data["ip_version"] not in (4, 6):
        return None, f"无效 IP 版本: {data['ip_version']}"

    # 端口范围校验
    for port_field in ("src_port", "dst_port"):
        if port_field in data:
            port = data[port_field]
            if not isinstance(port, int) or port < 0 or port > 65535:
                return None, f"无效端口 {port_field}: {port}"

    # 过滤未知字段，只保留定义内的字段
    clean = {k: v for k, v in data.items() if k in ALL_FIELDS}
    return clean, None


# ══════════════════════════════════════════════════════════════════
#  API 路由
# ══════════════════════════════════════════════════════════════════

# ─── 健康检查（无需认证）───
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "NetMonitor Pro API", "version": "1.0.0"})


# ─── 获取 JWT Token ───
@app.route("/api/v1/auth/token", methods=["POST"])
def auth_token():
    """
    请求体: {"api_key": "...", "device_id": "optional-device-id"}
    返回:   {"token": "jwt...", "expires_at": "ISO8601"}
    """
    data = request.get_json(silent=True) or {}
    api_key = data.get("api_key", "")

    if api_key != config.API_KEY:
        return jsonify({"error": "API 密钥无效", "code": "AUTH_FAILED"}), 403

    device_id = data.get("device_id")
    token, expires = create_token(device_id)

    # 记录 token hash（用于审计/吊销）
    db = get_db()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db.execute(
        "INSERT INTO api_tokens (token_hash, device_id, expires_at) VALUES (?, ?, ?)",
        (token_hash, device_id, expires)
    )
    db.commit()

    log.info("签发 Token → device_id=%s, expires=%s", device_id, expires)
    return jsonify({"token": token, "expires_at": expires})


# ─── 单条事件写入 ───
@app.route("/api/v1/ingest", methods=["POST"])
@require_auth
def ingest_single():
    """
    请求体: {"event_type": "TCP_CONNECT", "pid": 1234, ...}
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "请求体必须是有效 JSON"}), 400

    clean, err = validate_event(data)
    if err:
        return jsonify({"error": err, "code": "VALIDATION_FAILED"}), 422

    # 补充 device_id（从 token 中获取）
    if not clean.get("device_id"):
        clean["device_id"] = g.auth_payload.get("device_id")

    _insert_event(get_db(), clean)
    get_db().commit()

    return jsonify({"status": "ok", "inserted": 1})


# ─── 批量事件写入 ───
@app.route("/api/v1/ingest/batch", methods=["POST"])
@require_auth
def ingest_batch():
    """
    请求体: {"events": [{...}, {...}, ...]}
    最大: MAX_BATCH_SIZE 条/次
    """
    data = request.get_json(silent=True)
    if not data or "events" not in data:
        return jsonify({"error": "请求体必须包含 events 数组"}), 400

    events = data["events"]
    if not isinstance(events, list):
        return jsonify({"error": "events 必须是数组"}), 400

    if len(events) > config.MAX_BATCH_SIZE:
        return jsonify({
            "error": f"批量上限 {config.MAX_BATCH_SIZE} 条，收到 {len(events)} 条",
            "code": "BATCH_TOO_LARGE"
        }), 413

    db = get_db()
    device_id = g.auth_payload.get("device_id")
    inserted = 0
    errors = []

    for i, event in enumerate(events):
        clean, err = validate_event(event)
        if err:
            errors.append({"index": i, "error": err})
            continue
        if not clean.get("device_id"):
            clean["device_id"] = device_id
        _insert_event(db, clean)
        inserted += 1

    db.commit()

    result = {"status": "ok", "inserted": inserted, "total": len(events)}
    if errors:
        result["errors"] = errors[:20]  # 最多返回前 20 条错误
        result["error_count"] = len(errors)

    status_code = 200 if not errors else 207  # 207 Multi-Status
    return jsonify(result), status_code


def _insert_event(db: sqlite3.Connection, evt: dict):
    """插入单条事件到数据库"""
    columns = list(evt.keys())
    placeholders = ", ".join(["?"] * len(columns))
    col_names = ", ".join(columns)
    values = [evt[c] for c in columns]

    db.execute(
        f"INSERT INTO events ({col_names}) VALUES ({placeholders})",
        values
    )


# ─── 事件查询 ───
@app.route("/api/v1/events", methods=["GET"])
@require_auth
def query_events():
    """
    查询参数:
      - start:      起始时间 (ISO8601)
      - end:        结束时间 (ISO8601)
      - event_type: 事件类型过滤
      - comm:       进程名过滤
      - dst_addr:   目标 IP 过滤
      - dst_port:   目标端口过滤
      - uid:        UID 过滤
      - protocol:   协议过滤
      - device_id:  设备 ID 过滤
      - limit:      返回条数 (默认 100, 最大 1000)
      - offset:     偏移量 (分页)
      - order:      排序 asc/desc (默认 desc)
    """
    db = get_db()

    # 构建动态查询
    conditions = []
    params = []

    if request.args.get("start"):
        conditions.append("timestamp >= ?")
        params.append(request.args["start"])
    if request.args.get("end"):
        conditions.append("timestamp <= ?")
        params.append(request.args["end"])
    if request.args.get("event_type"):
        conditions.append("event_type = ?")
        params.append(request.args["event_type"])
    if request.args.get("comm"):
        conditions.append("comm LIKE ?")
        params.append(f"%{request.args['comm']}%")
    if request.args.get("dst_addr"):
        conditions.append("dst_addr = ?")
        params.append(request.args["dst_addr"])
    if request.args.get("dst_port"):
        conditions.append("dst_port = ?")
        params.append(int(request.args["dst_port"]))
    if request.args.get("uid"):
        conditions.append("uid = ?")
        params.append(int(request.args["uid"]))
    if request.args.get("protocol"):
        conditions.append("protocol = ?")
        params.append(request.args["protocol"])
    if request.args.get("device_id"):
        conditions.append("device_id = ?")
        params.append(request.args["device_id"])

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # 分页 & 排序
    limit = min(int(request.args.get("limit", 100)), 1000)
    offset = int(request.args.get("offset", 0))
    order = "DESC" if request.args.get("order", "desc").lower() == "desc" else "ASC"

    # 查询总数
    count_sql = f"SELECT COUNT(*) FROM events WHERE {where_clause}"
    total = db.execute(count_sql, params).fetchone()[0]

    # 查询数据
    query_sql = f"""
        SELECT * FROM events
        WHERE {where_clause}
        ORDER BY id {order}
        LIMIT ? OFFSET ?
    """
    rows = db.execute(query_sql, params + [limit, offset]).fetchall()
    events = [dict(row) for row in rows]

    return jsonify({
        "total": total,
        "limit": limit,
        "offset": offset,
        "count": len(events),
        "events": events,
    })


# ─── 统计聚合 ───
@app.route("/api/v1/stats", methods=["GET"])
@require_auth
def stats():
    """
    查询参数:
      - period:  统计时间范围 (1h, 6h, 24h, 7d, 30d)
      - group_by: 聚合维度 (event_type, comm, dst_addr, dst_port, protocol)
    """
    db = get_db()

    period_map = {
        "1h": 1, "6h": 6, "24h": 24,
        "7d": 24 * 7, "30d": 24 * 30,
    }
    period = request.args.get("period", "24h")
    hours = period_map.get(period, 24)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    group_by = request.args.get("group_by", "event_type")
    valid_groups = {"event_type", "comm", "dst_addr", "dst_port", "protocol", "uid"}
    if group_by not in valid_groups:
        return jsonify({"error": f"无效聚合维度: {group_by}（允许: {valid_groups})"}), 400

    # 总览统计
    overview = db.execute(
        "SELECT COUNT(*) as total, "
        "SUM(CASE WHEN event_type='TCP_CONNECT_RET' AND connect_result!='success' THEN 1 ELSE 0 END) as errors, "
        "SUM(bytes_sent) as total_bytes "
        "FROM events WHERE received_at >= ?",
        (since,)
    ).fetchone()

    # 分组统计
    group_sql = f"""
        SELECT {group_by}, COUNT(*) as count, SUM(bytes_sent) as total_bytes
        FROM events
        WHERE received_at >= ?
        GROUP BY {group_by}
        ORDER BY count DESC
        LIMIT 50
    """
    groups = db.execute(group_sql, (since,)).fetchall()

    # 时间线（按小时聚合）
    timeline_sql = """
        SELECT strftime('%Y-%m-%dT%H:00:00Z', received_at) as hour,
               COUNT(*) as count
        FROM events
        WHERE received_at >= ?
        GROUP BY hour
        ORDER BY hour ASC
    """
    timeline = db.execute(timeline_sql, (since,)).fetchall()

    return jsonify({
        "period": period,
        "since": since,
        "overview": {
            "total_events": overview["total"] or 0,
            "error_count": overview["errors"] or 0,
            "total_bytes": overview["total_bytes"] or 0,
        },
        "group_by": group_by,
        "groups": [dict(row) for row in groups],
        "timeline": [dict(row) for row in timeline],
    })


# ─── 数据清理 ───
@app.route("/api/v1/admin/cleanup", methods=["POST"])
@require_auth
def cleanup():
    """清理过期数据（保留天数由配置决定）"""
    db = get_db()
    cutoff = (datetime.now(timezone.utc) - timedelta(days=config.DATA_RETENTION_DAYS)).isoformat()

    cursor = db.execute("DELETE FROM events WHERE received_at < ?", (cutoff,))
    deleted = cursor.rowcount
    db.commit()

    # 清理过期 token
    cursor2 = db.execute(
        "DELETE FROM api_tokens WHERE expires_at < ?",
        (datetime.now(timezone.utc).isoformat(),)
    )
    tokens_deleted = cursor2.rowcount
    db.commit()

    log.info("数据清理: 删除 %d 条事件, %d 条过期 Token", deleted, tokens_deleted)
    return jsonify({
        "status": "ok",
        "events_deleted": deleted,
        "tokens_deleted": tokens_deleted,
        "retention_days": config.DATA_RETENTION_DAYS,
    })


# ─── 导出 ───
@app.route("/api/v1/export", methods=["GET"])
@require_auth
def export_events():
    """导出事件为 JSON Lines（流式响应）"""
    import io

    db = get_db()
    start = request.args.get("start")
    end = request.args.get("end")

    conditions = []
    params = []
    if start:
        conditions.append("timestamp >= ?")
        params.append(start)
    if end:
        conditions.append("timestamp <= ?")
        params.append(end)

    where = " AND ".join(conditions) if conditions else "1=1"
    rows = db.execute(
        f"SELECT * FROM events WHERE {where} ORDER BY id ASC",
        params
    ).fetchall()

    import json
    lines = []
    for row in rows:
        lines.append(json.dumps(dict(row), ensure_ascii=False))

    return app.response_class(
        "\n".join(lines) + "\n",
        mimetype="application/jsonl",
        headers={"Content-Disposition": "attachment; filename=netmon_export.jsonl"}
    )


# ══════════════════════════════════════════════════════════════════
#  启动
# ══════════════════════════════════════════════════════════════════

def main():
    init_db()
    log.info("=" * 50)
    log.info("NetMonitor Pro API Server v1.0.0")
    log.info("数据库: %s", config.DATABASE_PATH)
    log.info("监听: %s:%d", config.HOST, config.PORT)
    log.info("JWT 有效期: %d 小时", config.JWT_EXPIRY_HOURS)
    log.info("数据保留: %d 天", config.DATA_RETENTION_DAYS)
    log.info("批量上限: %d 条/次", config.MAX_BATCH_SIZE)
    log.info("=" * 50)

    if config.API_KEY == "changeme-netmonitor-2024":
        log.warning("⚠️  使用默认 API_KEY！生产环境请设置 NETMON_API_KEY 环境变量")

    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
    )


if __name__ == "__main__":
    main()
