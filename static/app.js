/* 网站访问日志可视化分析工具 —— 前端逻辑（ECharts 图表 + 表格 + 上传/导出） */

// 调色板：浅色 / 深色两套（与 style.css 中 CSS 变量保持一致）
const PALETTE = {
  light: {
    surface: '#fcfcfb', text: '#0b0b0b', text2: '#52514e', muted: '#898781',
    grid: '#e1e0d9', axis: '#c3c2b7',
    cat: ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6', '#e34948'],
    blue: '#2a78d6', orange: '#eb6834',
    good: '#0ca30c', warning: '#eda100', critical: '#d03b3b',
  },
  dark: {
    surface: '#1a1a19', text: '#f0efec', text2: '#c3c2b7', muted: '#898781',
    grid: '#2c2c2a', axis: '#383835',
    cat: ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767'],
    blue: '#3987e5', orange: '#d95926',
    good: '#0ca30c', warning: '#c98500', critical: '#d03b3b',
  },
};

let currentTheme = 'light';
let currentData = null;
let activeTab = 'attack';
const charts = {};

function getTheme() {
  const saved = document.documentElement.dataset.theme;
  if (saved) return saved;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  currentTheme = t;
  if (currentData) render(currentData);
}

function chrome(p) {
  return {
    textStyle: { color: p.text, fontFamily: 'system-ui, -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif' },
    tooltip: {
      backgroundColor: p.surface, borderColor: p.axis, borderWidth: 1,
      textStyle: { color: p.text }, extraCssText: 'box-shadow:0 2px 12px rgba(0,0,0,.12);',
    },
    legend: { textStyle: { color: p.text2 } },
  };
}

function initChart(id) {
  if (!charts[id]) charts[id] = echarts.init(document.getElementById(id));
  return charts[id];
}

/* ---- 各图表渲染 ---- */
function renderTrend(p, trend) {
  const c = initChart('chartTrend');
  c.setOption({
    ...chrome(p),
    grid: { left: 48, right: 16, top: 16, bottom: 32 },
    xAxis: {
      type: 'category', data: trend.map(t => t.label), boundaryGap: false,
      axisLine: { lineStyle: { color: p.axis } }, axisLabel: { color: p.muted },
      axisTick: { show: false },
    },
    yAxis: {
      type: 'value', splitLine: { lineStyle: { color: p.grid } },
      axisLabel: { color: p.muted }, name: '请求数', nameTextStyle: { color: p.muted },
    },
    tooltip: { ...chrome(p).tooltip, trigger: 'axis' },
    series: [{
      name: '请求数', type: 'line', data: trend.map(t => t.count),
      smooth: true, symbolSize: 8, lineStyle: { width: 2, color: p.blue },
      itemStyle: { color: p.blue },
      areaStyle: { color: p.blue, opacity: 0.10 },
    }],
  });
}

function statusColor(p, code) {
  if (code < 300) return p.good;
  if (code < 400) return p.blue;
  if (code < 500) return p.warning;
  return p.critical;
}

function renderStatus(p, dist) {
  const c = initChart('chartStatus');
  c.setOption({
    ...chrome(p),
    tooltip: { ...chrome(p).tooltip, trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { ...chrome(p).legend, bottom: 0, type: 'scroll' },
    series: [{
      type: 'pie', radius: ['42%', '68%'], center: ['50%', '46%'],
      itemStyle: { borderColor: p.surface, borderWidth: 2 },
      label: { color: p.text2, formatter: '{b}\n{d}%' },
      data: dist.map(d => ({
        name: String(d.status), value: d.count,
        itemStyle: { color: statusColor(p, d.status) },
      })),
    }],
  });
}

function renderMethod(p, dist) {
  const c = initChart('chartMethod');
  c.setOption({
    ...chrome(p),
    tooltip: { ...chrome(p).tooltip, trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { ...chrome(p).legend, bottom: 0, type: 'scroll' },
    series: [{
      type: 'pie', radius: ['42%', '68%'], center: ['50%', '46%'],
      itemStyle: { borderColor: p.surface, borderWidth: 2 },
      label: { color: p.text2, formatter: '{b}\n{d}%' },
      data: dist.map((d, i) => ({
        name: d.method, value: d.count,
        itemStyle: { color: p.cat[i % p.cat.length] },
      })),
    }],
  });
}

function renderBar(id, p, items, nameKey, valueKey, color) {
  const c = initChart(id);
  const data = items.slice().reverse(); // 横向柱状图：大的在顶部
  c.setOption({
    ...chrome(p),
    grid: { left: 8, right: 56, top: 8, bottom: 8, containLabel: true },
    xAxis: {
      type: 'value', splitLine: { lineStyle: { color: p.grid } },
      axisLabel: { color: p.muted },
    },
    yAxis: {
      type: 'category', data: data.map(d => d[nameKey]),
      axisLine: { lineStyle: { color: p.axis } },
      axisLabel: {
        color: p.text2, width: 140, overflow: 'truncate',
        formatter: v => v.length > 22 ? v.slice(0, 21) + '…' : v,
      },
    },
    series: [{
      type: 'bar', data: data.map(d => d[valueKey]),
      barWidth: 16, itemStyle: { color, borderRadius: [0, 4, 4, 0] },
      label: { show: true, position: 'right', color: p.text2 },
    }],
  });
}

function renderRules(p, summary) {
  const c = initChart('chartRules');
  c.setOption({
    ...chrome(p),
    grid: { left: 48, right: 16, top: 16, bottom: 40 },
    xAxis: {
      type: 'category', data: summary.map(r => r.rule),
      axisLine: { lineStyle: { color: p.axis } }, axisLabel: { color: p.muted, interval: 0 },
    },
    yAxis: { type: 'value', splitLine: { lineStyle: { color: p.grid } }, axisLabel: { color: p.muted } },
    series: [{
      type: 'bar', data: summary.map(r => r.count),
      barWidth: 20, itemStyle: { color: p.critical, borderRadius: [4, 4, 0, 0] },
      label: { show: true, position: 'top', color: p.text2 },
    }],
  });
}

/* ---- 异常明细表格 ---- */
const TAB_DEFS = {
  attack: {
    cols: ['时间', 'IP', '方法', 'URL', '状态码', '规则', '说明'],
    rows: a => a.attack_requests.map(r => [
      r.time, r.ip, r.method, r.url, r.status, r.rule, r.desc,
    ]),
  },
  freq: {
    cols: ['IP', '请求次数'],
    rows: a => a.high_freq_ips.map(r => [r.ip, r.count]),
  },
  err: {
    cols: ['IP', '总请求', '错误数', '错误率', '主要状态码'],
    rows: a => a.error_anomalies.map(r => [r.ip, r.total, r.errors, (r.error_rate * 100).toFixed(1) + '%', r.top_status]),
  },
  ua: {
    cols: ['User-Agent', '次数'],
    rows: a => a.suspicious_uas.map(r => [r.ua, r.count]),
  },
  brute: {
    cols: ['IP', '尝试次数', '失败次数'],
    rows: a => a.brute_force.map(r => [r.ip, r.attempts, r.failures]),
  },
};

function renderTable() {
  const def = TAB_DEFS[activeTab];
  const rows = def.rows(currentData.anomalies);
  const table = document.getElementById('anomTable');
  let html = '<thead><tr>' + def.cols.map(c => `<th>${c}</th>`).join('') + '</tr></thead><tbody>';
  if (rows.length === 0) {
    html += `<tr><td class="empty" colspan="${def.cols.length}">无匹配记录</td></tr>`;
  } else {
    html += rows.map(r => {
      const cells = r.map((v, i) => {
        if (v === null || v === undefined) v = '';
        if (activeTab === 'attack' && i === 5) return `<td><span class="rule-tag">${v}</span></td>`;
        if (typeof v === 'number') return `<td class="num">${v.toLocaleString()}</td>`;
        if (i === 1 && (activeTab === 'attack')) return `<td class="mono">${v}</td>`;
        if (activeTab === 'attack' && i === 3) return `<td class="mono">${v}</td>`;
        return `<td>${v}</td>`;
      });
      return '<tr>' + cells.join('') + '</tr>';
    }).join('');
  }
  html += '</tbody>';
  table.innerHTML = html;
}

/* ---- 主渲染 ---- */
function render(result) {
  currentData = result;
  const p = PALETTE[currentTheme];
  const s = result.stats, a = result.anomalies;

  document.getElementById('summary').hidden = false;
  document.getElementById('anomalies').hidden = false;
  document.getElementById('cTotal').textContent = s.total.toLocaleString();
  document.getElementById('cIPs').textContent = s.unique_ips.toLocaleString();
  const errCount = s.status_dist.filter(d => d.status >= 400).reduce((x, d) => x + d.count, 0);
  document.getElementById('cErr').textContent = errCount.toLocaleString();
  const anomCount = a.attack_requests.length + a.high_freq_ips.length + a.error_anomalies.length
    + a.suspicious_uas.length + a.brute_force.length;
  document.getElementById('cAnom').textContent = anomCount.toLocaleString();

  renderTrend(p, s.time_trend);
  renderStatus(p, s.status_dist);
  renderMethod(p, s.method_dist);
  renderBar('chartIp', p, s.top_ips, 'ip', 'count', p.blue);
  renderBar('chartUrl', p, s.top_urls, 'url', 'count', p.orange);
  renderRules(p, a.attack_rule_summary);
  renderTable();
  document.getElementById('exportBtn').disabled = false;
}

/* ---- 加载画面 ---- */
const loadingEl = document.getElementById('loading');
let loadingTimer = null;
let loadingShownAt = 0;

function hideLoading() {
  clearTimeout(loadingTimer);
  loadingEl.classList.remove('show');
}

function setLoading(on) {
  if (on) {
    clearTimeout(loadingTimer);
    loadingShownAt = Date.now();
    loadingEl.classList.add('show');            // 触发进场动画
    loadingTimer = setTimeout(hideLoading, 3000);  // 最多显示 3 秒
  } else {
    // 数据加载完成时：至少显示 1 秒保证动画可看到，再淡出
    const shown = Date.now() - loadingShownAt;
    clearTimeout(loadingTimer);
    loadingTimer = setTimeout(hideLoading, Math.max(0, 1000 - shown));
  }
}

/* ---- 请求与事件 ---- */

async function loadFrom(url, options) {
  setLoading(true);
  try {
    const res = await fetch(url, options);
    const data = await res.json();
    if (data.error) { alert(data.error); return; }
    document.getElementById('fileInfo').textContent = `${data.filename} · 解析 ${data.total.toLocaleString()} 条`;
    render(data.result);
  } catch (e) {
    alert('加载失败：' + e.message);
  } finally {
    setLoading(false);
  }
}

document.getElementById('fileInput').addEventListener('change', e => {
  const file = e.target.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append('file', file);
  loadFrom('/api/upload', { method: 'POST', body: fd });
  e.target.value = '';
});

document.getElementById('sampleBtn').addEventListener('click', () => loadFrom('/api/sample'));
document.getElementById('exportBtn').addEventListener('click', () => { window.location = '/api/export'; });

document.getElementById('tabs').addEventListener('click', e => {
  if (!e.target.classList.contains('tab')) return;
  activeTab = e.target.dataset.t;
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t === e.target));
  renderTable();
});

document.getElementById('themeBtn').addEventListener('click', () => {
  setTheme(currentTheme === 'dark' ? 'light' : 'dark');
});

window.addEventListener('resize', () => Object.values(charts).forEach(c => c.resize()));

// 初始化主题
setTheme(getTheme());

// 页面打开时自动加载示例日志，直接展示图表（无需手动点击）
loadFrom('/api/sample');
