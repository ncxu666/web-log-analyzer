# -*- coding: utf-8 -*-
"""异常检测模块：基于可配置规则的检测（config.json 中的阈值与规则）。"""
import re
from collections import Counter, defaultdict


def _compile_rules(rules):
    """把规则列表编译成带正则的规则对象。"""
    compiled = []
    for rule in rules:
        compiled.append({
            'name': rule['name'],
            'desc': rule.get('desc', ''),
            're': re.compile(rule['pattern'], re.IGNORECASE),
        })
    return compiled


def detect(entries, config):
    rules = _compile_rules(config.get('attack_rules', []))
    high_threshold = config.get('high_freq_threshold', 200)
    err_rate = config.get('error_rate_threshold', 0.5)
    err_min = config.get('error_min_count', 20)
    brute_min = config.get('brute_force_min_failures', 5)
    ua_keywords = [k.lower() for k in config.get('suspicious_ua_keywords', [])]
    login_pat = re.compile(
        '|'.join(re.escape(p) for p in config.get('login_endpoints', [])),
        re.IGNORECASE,
    )

    # 1) 单 IP 高频访问（疑似扫描 / 爆破）
    ip_counts = Counter(e['ip'] for e in entries)
    high_freq = [
        {'ip': ip, 'count': c}
        for ip, c in ip_counts.most_common() if c >= high_threshold
    ]

    # 2) 4xx/5xx 错误率异常（按 IP 统计）
    per_ip = defaultdict(lambda: {'total': 0, 'err': 0, 'statuses': Counter()})
    for e in entries:
        s = per_ip[e['ip']]
        s['total'] += 1
        s['statuses'][e['status']] += 1
        if e['status'] >= 400:
            s['err'] += 1
    error_anomalies = []
    for ip, s in per_ip.items():
        if s['total'] >= err_min and s['err'] / s['total'] >= err_rate:
            error_anomalies.append({
                'ip': ip,
                'total': s['total'],
                'errors': s['err'],
                'error_rate': round(s['err'] / s['total'], 3),
                'top_status': s['statuses'].most_common(1)[0][0] if s['statuses'] else None,
            })
    error_anomalies.sort(key=lambda x: -x['errors'])

    # 3) 可疑 User-Agent
    ua_counts = Counter((e['ua'] or '-') for e in entries)
    suspicious_uas = []
    for ua, c in ua_counts.items():
        lua = ua.lower()
        if ua in ('', '-') or any(k in lua for k in ua_keywords):
            suspicious_uas.append({'ua': ua, 'count': c})
    suspicious_uas.sort(key=lambda x: -x['count'])

    # 4) 攻击特征请求（规则匹配，每条请求归入第一条命中规则）
    attack_requests = []
    for e in entries:
        target = e.get('url_decoded') or e['url']
        for rule in rules:
            if rule['re'].search(target):
                attack_requests.append({
                    'rule': rule['name'],
                    'desc': rule['desc'],
                    'ip': e['ip'],
                    'method': e['method'],
                    'url': e['url'],
                    'status': e['status'],
                    'time': e['time_str'],
                })
                break
    by_rule = Counter(a['rule'] for a in attack_requests)
    attack_rule_summary = [
        {'rule': name, 'count': c} for name, c in by_rule.most_common()
    ]

    # 5) 暴力破解：登录接口 + 大量 4xx/401/403，按 IP 聚合
    brute = defaultdict(lambda: {'attempts': 0, 'failures': 0})
    for e in entries:
        if login_pat.search(e['path']):
            brute[e['ip']]['attempts'] += 1
            if e['status'] in (400, 401, 403):
                brute[e['ip']]['failures'] += 1
    brute_force = [
        {'ip': ip, 'attempts': v['attempts'], 'failures': v['failures']}
        for ip, v in brute.items() if v['failures'] >= brute_min
    ]
    brute_force.sort(key=lambda x: -x['failures'])

    return {
        'high_freq_ips': high_freq,
        'error_anomalies': error_anomalies,
        'suspicious_uas': suspicious_uas,
        'attack_requests': attack_requests,
        'attack_rule_summary': attack_rule_summary,
        'brute_force': brute_force,
    }
