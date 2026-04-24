#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetMonitor Pro — Gunicorn 生产部署配置 (新增文件)
文件位置: server/gunicorn.conf.py

用法:
  cd server && gunicorn -c gunicorn.conf.py app:app
"""

import multiprocessing
import os

# 监听地址
bind = os.getenv("NETMON_BIND", "0.0.0.0:5000")

# Worker 数量 = CPU 核心数 × 2 + 1
workers = int(os.getenv("NETMON_WORKERS",
                        multiprocessing.cpu_count() * 2 + 1))

# Worker 类型
worker_class = "sync"

# 超时
timeout = 30
graceful_timeout = 10
keepalive = 5

# 日志
accesslog = "-"
errorlog = "-"
loglevel = os.getenv("NETMON_LOG_LEVEL", "info").lower()

# 安全
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

# 进程名
proc_name = "netmonitor-pro"

# 预加载应用（节省内存）
preload_app = True
