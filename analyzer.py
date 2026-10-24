# -*- coding: utf-8 -*-
"""统计分析模块：访问量趋势、Top IP/URL、状态码/请求方法分布。"""
from collections import Counter
from datetime import datetime


def _format_label(epoch, bucket_sec):
    """把时间桶起点格式化为坐标轴标签。"""
    dt = datetime.fromtimestamp(epoch)
    if bucket_sec >= 86400:
        return dt.strftime('%m-%d')
    if bucket_sec >= 3600:
        return dt.strftime('%m-%d %H:%M')
    return dt.strftime('%H:%M')


def analyze(entries, top_n=10):
    total = len(entries)

    ip_counts = Counter(e['ip'] for e in entries)
    url_counts = Counter(e['path'] for e in entries)
    status_counts = Counter(e['status'] for e in entries)
    method_counts = Counter(e['method'] for e in entries)

    # ---- 访问量趋势：按时间跨度自适应分桶 ----
    times = [e['time'] for e in entries if e['time'] is not None]
    time_trend = []
    if times:
        span = max(times) - min(times)
        if span > 86400 * 7:
            bucket = 86400            # 超过一周 -> 按天
        elif span > 86400:
            bucket = 3600             # 超过一天 -> 按小时
        elif span <= 3600:
            bucket = 300              # 一小时以内 -> 按 5 分钟
        else:
            bucket = 300              # 一天以内 -> 按 5 分钟

        buckets = Counter(int(t) - int(t) % bucket for t in times)
        time_trend = [
            {'epoch': b, 'label': _format_label(b, bucket), 'count': c}
            for b, c in sorted(buckets.items())
        ]

    return {
        'total': total,
        'unique_ips': len(ip_counts),
        'time_trend': time_trend,
        'top_ips': [{'ip': k, 'count': v} for k, v in ip_counts.most_common(top_n)],
        'top_urls': [{'url': k, 'count': v} for k, v in url_counts.most_common(top_n)],
        'status_dist': [{'status': k, 'count': v} for k, v in sorted(status_counts.items())],
        'method_dist': [{'method': k, 'count': v} for k, v in method_counts.most_common()],
    }
