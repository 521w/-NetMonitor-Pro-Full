# NetMonitor Pro Full — 优化修改说明

## 📁 文件目录结构 & 修改标注

```
NetMonitor-Pro-Full/
│
├── ebpf/                                ← eBPF 内核态抓包模块
│   ├── netmon_kern.c                    ✅ 已优化 (消除v4/v6重复、先过滤再reserve、提取公共函数、LRU防泄漏)
│   ├── netmon_user.py                   ✅ 已优化 (动态boot time、指数退避、异常容忍、新增device-id)
│   └── Makefile                         ✅ 已优化 (自动检测内核头、新增install/format/check目标)
│
├── server/                              ← Flask REST API 服务端
│   ├── app.py                           ✅ 已优化 (SQL注入修复、速率限制、流式导出、安全参数解析、admin角色)
│   ├── config.py                        ✅ 已优化 (JWT原子写入、配置校验、新增速率限制配置)
│   ├── requirements.txt                 ✅ 已修复 (原文件缺.txt后缀、新增flask-limiter和gunicorn)
│   └── gunicorn.conf.py                 🆕 新增 (生产部署Gunicorn配置)
│
├── android/                             ← Android 客户端
│   ├── build.gradle.kts                 ✅ 已优化 (AGP和Kotlin版本升级)
│   ├── settings.gradle.kts              🆕 新增 (项目设置，含JitPack仓库)
│   └── app/
│       ├── build.gradle.kts             ✅ 已优化 (targetSdk=35、开启混淆、新增网络库)
│       └── proguard-rules.pro           🆕 新增 (混淆规则，配合isMinifyEnabled=true)
│
├── scripts/
│   └── build_all.sh                     ✅ 已重写 (原脚本是假的！现在真正执行编译)
│
└── README_优化说明.md                    🆕 本文件
```

## 🔴 致命问题修复 (3个)

| # | 文件 | 问题 | 修复方式 |
|---|------|------|----------|
| 1 | server/app.py | SQL注入：列名f-string直接拼SQL | 双重白名单(frozenset) + 参数化占位符 |
| 2 | server/app.py | 无速率限制，可被DoS/暴力刷token | 集成flask-limiter，分端点限速 |
| 3 | scripts/build_all.sh | 假脚本！echo打印命令不执行 | 完全重写，真正编译+全模块构建 |

## 🔴 高危问题修复 (5个)

| # | 文件 | 问题 | 修复方式 |
|---|------|------|----------|
| 1 | server/app.py | export全量加载OOM | 改为generator流式响应 |
| 2 | server/app.py | 参数解析无try/except | 新增safe_int/safe_str安全函数 |
| 3 | server/app.py | cleanup无权限区分 | 新增require_admin装饰器 |
| 4 | ebpf/netmon_user.py | ReportWorker静默丢数据 | 指数退避+超限告警+计数保护 |
| 5 | scripts/build_all.sh | zip打包.git目录 | 排除.git和敏感文件 |

## 🟡 中危问题修复 (10+个)

- eBPF: TCP v4/v6 kretprobe ~80行重复代码 → 统一handle_tcp_connect_ret()
- eBPF: UDP v4/v6 handler重复 → 统一handle_udp_sendmsg()
- eBPF: UDP先reserve再过滤浪费ringbuf → 先过滤再reserve
- eBPF: connect_args map泄漏风险 → 改用LRU_HASH
- Python: boot time一次性计算会漂移 → 动态计算
- Python: JsonLogger磁盘满崩溃 → 异常捕获
- Python: 主循环一次错误终止 → 计数容忍重试
- Server: PRAGMA每次请求执行 → 首次连接单次执行
- Server: cleanup两次commit → 合并单一事务
- Server: JWT secret TOCTOU竞态 → tempfile原子写入
- Server: 默认API_KEY只warning → 生产环境强制退出
- Android: targetSdk=34过时 → 升级到35
- Android: Release未混淆 → 开启minify+shrink
- Android: 缺少网络库 → 新增OkHttp+Retrofit

## 🚀 部署方式

### eBPF 探针
```bash
cd ebpf
make              # 编译内核探针
sudo python3 netmon_user.py -v \
  --api-url http://your-server:5000 \
  --api-token YOUR_TOKEN \
  --device-id "node-01"
```

### 服务端 (开发)
```bash
cd server
pip install -r requirements.txt
export NETMON_API_KEY="your-secure-key"
python3 app.py
```

### 服务端 (生产)
```bash
cd server
pip install -r requirements.txt
export NETMON_API_KEY="your-secure-key"
gunicorn -c gunicorn.conf.py app:app
```

### 全量构建
```bash
chmod +x scripts/build_all.sh
./scripts/build_all.sh
```