# -*- coding: utf-8 -*-
"""日志解析模块：解析 Nginx / Apache combined 格式访问日志。

combined 格式示例：
192.168.1.1 - - [21/Oct/2026:13:55:36 +0800] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0 ..."
字段：IP  标识  用户  [时间]  "请求方法 URL 协议"  状态码  字节数  "来源页"  "User-Agent"
"""
import re
from datetime import datetime
from urllib.parse import unquote

# combined 格式整行正则
COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

# 请求行 "METHOD URL PROTOCOL" 拆分
REQUEST_RE = re.compile(r'^(?P<method>\S+)\s+(?P<url>\S+)\s*(?P<proto>HTTP/\S+)?')

TIME_FMT = '%d/%b/%Y:%H:%M:%S %z'


def parse_time(time_str):
    """把 combined 格式的时间字符串转为 epoch 秒，失败返回 None。"""
    try:
        return datetime.strptime(time_str, TIME_FMT).timestamp()
    except (ValueError, TypeError):
        try:
            # 个别日志缺少时区，退化为本地时间
            return datetime.strptime(time_str[:20], '%d/%b/%Y:%H:%M:%S').timestamp()
        except (ValueError, TypeError):
            return None


def parse_line(line):
    """解析单行日志，成功返回 dict，失败返回 None。"""
    line = line.strip()
    if not line:
        return None
    m = COMBINED_RE.match(line)
    if not m:
        return None

    req = REQUEST_RE.match(m.group('request') or '')
    method = (req.group('method') if req else '-').upper()
    url = req.group('url') if req else (m.group('request') or '-')

    status = int(m.group('status'))
    size_str = m.group('size')
    try:
        size = int(size_str)
    except ValueError:
        size = 0

    return {
        'ip': m.group('ip'),
        'time': parse_time(m.group('time')),   # epoch 秒
        'time_str': m.group('time'),
        'method': method,
        'url': url,
        'url_decoded': unquote(url, errors='replace'),  # URL 解码，供攻击特征匹配
        'path': url.split('?', 1)[0],          # 去掉 query 后的路径，用于 Top URL 统计
        'status': status,
        'size': size,
        'referer': m.group('referer'),
        'ua': m.group('ua'),
    }


def parse_log(text):
    """解析整段日志文本，返回条目列表（跳过无法解析的行）。"""
    entries = []
    for line in text.splitlines():
        entry = parse_line(line)
        if entry:
            entries.append(entry)
    return entries
