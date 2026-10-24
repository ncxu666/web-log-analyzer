# -*- coding: utf-8 -*-
"""生成演示用访问日志（combined 格式），混合正常流量与攻击流量。

运行：python generate_sample.py
输出：sample_logs/access.log
"""
import random
from datetime import datetime, timedelta

random.seed(42)

NORMAL_PATHS = [
    '/', '/index.html', '/about.html', '/products.html', '/contact.html',
    '/assets/css/main.css', '/assets/js/app.js', '/assets/img/logo.png',
    '/blog/post-1.html', '/blog/post-2.html', '/api/v1/users', '/api/v1/posts',
    '/search?q=flask', '/category/tech', '/favicon.ico',
]
NORMAL_UA = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36',
]
ATTACK_PATHS = [
    # SQL 注入（空格/引号做 URL 编码，贴近真实攻击流量）
    "/index.php?id=1%27%20OR%20%271%27%3D%271",
    "/index.php?id=-1%20UNION%20SELECT%20username,password%20FROM%20users",
    "/product.php?id=1%20AND%20SLEEP(5)",
    # 路径遍历
    "/../../../../etc/passwd",
    "/..%2f..%2f..%2fetc%2fpasswd",
    "/%2e%2e/%2e%2e/winnt/system32/cmd.exe",
    "/cgi-bin/../../bin/sh",
    # XSS 跨站脚本
    "/index.php?name=%3Cscript%3Ealert(1)%3C/script%3E",
    "/page?url=javascript:alert(document.cookie)",
    # 敏感文件探测
    "/.env",
    "/wp-config.php.bak",
    "/phpmyadmin/",
    "/server-status",
    "/.git/config",
    # 命令注入
    "/index.cgi?cmd=|id|",
    "/ping?host=127.0.0.1;id",
]
SCANNER_UA = [
    'sqlmap/1.7#stable (http://sqlmap.org)',
    'Nikto/2.1.6',
    'Mozilla/5.0 (compatible; Nmap Scripting Engine)',
    'gobuster/3.5',
    'python-requests/2.31.0',
    'curl/8.0.1',
    'WPScan v3.8',
    'masscan/1.3',
    '-',
]


def gen_line(ts, ip, method, path, status, size, ua):
    t = ts.strftime('%d/%b/%Y:%H:%M:%S +0800')
    request = f'{method} {path} HTTP/1.1'
    return f'{ip} - - [{t}] "{request}" {status} {size} "-" "{ua}"'


def main(n=15000):
    base = datetime(2026, 10, 22, 8, 0, 0)
    lines = []

    # 正常流量
    normal_ips = [f'203.0.113.{i}' for i in range(1, 200)]
    for _ in range(int(n * 0.82)):
        ts = base + timedelta(seconds=random.randint(0, 10 * 3600))
        ip = random.choice(normal_ips)
        path = random.choice(NORMAL_PATHS)
        status = random.choices([200, 200, 200, 200, 301, 304, 404, 500],
                                weights=[70, 12, 8, 4, 5, 5, 7, 3])[0]
        size = random.randint(200, 80000)
        ua = random.choice(NORMAL_UA)
        lines.append(gen_line(ts, ip, 'GET', path, status, size, ua))

    # 单 IP 高频扫描 / 爆破
    for _ in range(700):
        ts = base + timedelta(seconds=random.randint(0, 3600))
        path = random.choice(NORMAL_PATHS + ['/wp-login.php', '/login', '/admin/login'])
        status = random.choices([200, 301, 401, 403, 404], weights=[10, 10, 30, 30, 20])[0]
        lines.append(gen_line(ts, '198.51.100.66',
                              random.choice(['GET', 'POST']), path, status, 200,
                              random.choice(SCANNER_UA)))

    # 攻击特征请求
    attack_ips = ['203.0.113.250', '198.51.100.77', '192.0.2.13']
    for _ in range(500):
        ts = base + timedelta(seconds=random.randint(0, 10 * 3600))
        path = random.choice(ATTACK_PATHS)
        status = random.choices([200, 403, 404, 500], weights=[20, 30, 40, 10])[0]
        lines.append(gen_line(ts, random.choice(attack_ips),
                              random.choice(['GET', 'POST', 'PUT']), path, status,
                              random.randint(0, 400), random.choice(SCANNER_UA)))

    # 按时间排序（时间字符串为定长，可直接按字典序排序）
    lines.sort(key=lambda l: l.split('[', 1)[1][:20])

    with open('sample_logs/access.log', 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')
    print(f'已生成 {len(lines)} 行 -> sample_logs/access.log')


if __name__ == '__main__':
    main()
