# -*- coding: utf-8 -*-
"""Flask 主程序：日志导入、解析、统计、异常检测与结果导出。

运行：python app.py  然后浏览器打开 http://127.0.0.1:5000
"""
import io
import json
import csv

from flask import Flask, render_template, request, jsonify, Response

import parser as log_parser
import analyzer as analyzer_mod
import detector as detector_mod

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 上传上限 200MB

# 缓存最近一次分析结果（单用户演示足够）
CACHE = {'entries': [], 'result': None, 'filename': ''}


def load_config():
    with open('config.json', 'r', encoding='utf-8') as f:
        return json.load(f)


def run_analysis(entries, config):
    stats = analyzer_mod.analyze(entries, top_n=config.get('top_n', 10))
    anomalies = detector_mod.detect(entries, config)
    return {'stats': stats, 'anomalies': anomalies}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/upload', methods=['POST'])
def upload():
    file = request.files.get('file')
    if not file:
        return jsonify({'error': '未选择文件'}), 400

    raw = file.read()
    text = None
    for enc in ('utf-8', 'gbk', 'latin-1'):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return jsonify({'error': '文件编码无法识别'}), 400

    entries = log_parser.parse_log(text)
    if not entries:
        return jsonify({'error': '未解析到有效日志行，请确认是 Nginx/Apache combined 格式'}), 400

    result = run_analysis(entries, load_config())
    CACHE.update(entries=entries, result=result, filename=file.filename)
    return jsonify({'filename': file.filename, 'total': len(entries), 'result': result})


@app.route('/api/sample')
def sample():
    """加载内置示例日志，便于快速演示。"""
    with open('sample_logs/access.log', 'r', encoding='utf-8') as f:
        text = f.read()
    entries = log_parser.parse_log(text)
    result = run_analysis(entries, load_config())
    CACHE.update(entries=entries, result=result, filename='sample_logs/access.log')
    return jsonify({'filename': 'sample_logs/access.log', 'total': len(entries), 'result': result})


@app.route('/api/export')
def export():
    """把异常明细导出为 CSV（带 BOM，Excel 可直接打开）。"""
    if not CACHE['result']:
        return jsonify({'error': '请先导入日志'}), 400

    anomalies = CACHE['result']['anomalies']
    header = ['类型', '时间', 'IP', '方法', 'URL', '状态码', '说明']
    rows = [header]

    for a in anomalies['attack_requests']:
        rows.append([a['rule'], a['time'], a['ip'], a['method'], a['url'], a['status'], a['desc']])
    for a in anomalies['high_freq_ips']:
        rows.append(['高频访问', '', a['ip'], '', '', '', f"{a['count']} 次请求"])
    for a in anomalies['error_anomalies']:
        rows.append(['错误率异常', '', a['ip'], '', '', a['top_status'],
                     f"{a['errors']}/{a['total']} ({a['error_rate']:.0%})"])
    for a in anomalies['suspicious_uas']:
        rows.append(['可疑User-Agent', '', '', '', a['ua'], '', f"{a['count']} 次"])
    for a in anomalies['brute_force']:
        rows.append(['暴力破解', '', a['ip'], '', '', '', f"尝试{a['attempts']}次 / 失败{a['failures']}次"])

    buf = io.StringIO()
    csv.writer(buf).writerows(rows)
    data = '﻿' + buf.getvalue()  # BOM，保证 Excel 正确识别 UTF-8 中文
    return Response(
        data,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=anomalies.csv'},
    )


if __name__ == '__main__':
    # use_reloader=False：单进程运行，避免在 Windows 上残留子进程占用端口
    app.run(debug=True, use_reloader=False, host='127.0.0.1', port=5000)
