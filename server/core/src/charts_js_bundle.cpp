// Embedded SVG chart renderer for the dashboard's instruction-response
// visualization cards (issue #253). Same pattern as css_bundle.cpp and
// static_js_bundle.cpp — a single C++ string symbol consumed by server.cpp's
// /static/ route handler.
//
// Why vanilla SVG instead of Chart.js / uPlot:
//   * No vcpkg / vendored-JS license concern; everything ships AGPL.
//   * The chart shapes the engine produces (labels + series, x + series,
//     plus single/multi axis) only need a few hundred lines of rendering.
//   * Inlining keeps "one HTTP request → one drawn chart card" without an
//     extra network roundtrip for a third-party library.
//
// The bundled API is intentionally minimal:
//   YuzuCharts.render(targetEl, chartJson)
//
// where chartJson is exactly the payload returned by
// /api/v1/executions/{id}/visualization.

#include <string>

namespace yuzu::server {

// `extern` is load-bearing here: namespace-scope `const` variables have
// internal linkage by default in C++, which would make this symbol invisible
// to server.cpp's reference. Mirrors the pattern used by kHtmxJs in
// static_js_bundle.cpp.
extern const std::string kYuzuChartsJs = R"JS((function () {
  'use strict';

  // ── Colour palette (same hue family as the dashboard accents) ──────────
  var PALETTE = [
    '#5b9bd5', '#ed7d31', '#70ad47', '#ffc000', '#7030a0',
    '#4472c4', '#a5a5a5', '#264478', '#9e480e', '#636363'
  ];

  function color(i) { return PALETTE[i % PALETTE.length]; }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]);
    });
  }

  function svgEl(name, attrs, children) {
    var el = document.createElementNS('http://www.w3.org/2000/svg', name);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        el.setAttribute(k, attrs[k]);
      });
    }
    if (children) {
      children.forEach(function (c) {
        el.appendChild(typeof c === 'string'
          ? document.createTextNode(c) : c);
      });
    }
    return el;
  }

  // ── Tooltip (single shared element) ─────────────────────────────────────
  var tip;
  function showTip(evt, html) {
    if (!tip) {
      tip = document.createElement('div');
      tip.className = 'yuzu-chart-tip';
      tip.style.cssText = 'position:fixed;pointer-events:none;background:#222;'
        + 'color:#eee;padding:4px 8px;border-radius:4px;font:12px sans-serif;'
        + 'z-index:9999;box-shadow:0 2px 8px rgba(0,0,0,.4);';
      document.body.appendChild(tip);
    }
    tip.innerHTML = html;
    tip.style.left = (evt.clientX + 12) + 'px';
    tip.style.top = (evt.clientY + 12) + 'px';
    tip.style.display = 'block';
  }
  function hideTip() { if (tip) tip.style.display = 'none'; }

  // ── Pie ────────────────────────────────────────────────────────────────
  function renderPie(target, data) {
    var labels = data.labels || [];
    var series = (data.series && data.series[0]) || {data: []};
    var values = series.data || [];
    var total = values.reduce(function (a, b) { return a + b; }, 0);
    if (total <= 0) {
      target.appendChild(emptyState('No data to plot'));
      return;
    }
    var W = 360, H = 240, cx = 110, cy = 120, r = 90;
    var svg = svgEl('svg', {width: W, height: H, viewBox: '0 0 '+W+' '+H,
                             role: 'img', 'aria-label': data.title || 'pie chart'});
    var startAngle = -Math.PI / 2;
    values.forEach(function (v, i) {
      if (v <= 0) return;
      var sweep = (v / total) * Math.PI * 2;
      var endAngle = startAngle + sweep;
      var x1 = cx + r * Math.cos(startAngle);
      var y1 = cy + r * Math.sin(startAngle);
      var x2 = cx + r * Math.cos(endAngle);
      var y2 = cy + r * Math.sin(endAngle);
      var large = sweep > Math.PI ? 1 : 0;
      var d = 'M' + cx + ',' + cy + ' L' + x1 + ',' + y1
        + ' A' + r + ',' + r + ' 0 ' + large + ',1 ' + x2 + ',' + y2 + ' Z';
      var path = svgEl('path', {d: d, fill: color(i), stroke: '#1a1a1a',
                                  'stroke-width': 1});
      var pct = ((v / total) * 100).toFixed(1) + '%';
      path.addEventListener('mouseenter', function (e) {
        showTip(e, '<b>' + escapeHtml(labels[i] || '') + '</b><br>'
          + escapeHtml(String(v)) + ' (' + pct + ')');
      });
      path.addEventListener('mousemove', function (e) {
        showTip(e, '<b>' + escapeHtml(labels[i] || '') + '</b><br>'
          + escapeHtml(String(v)) + ' (' + pct + ')');
      });
      path.addEventListener('mouseleave', hideTip);
      svg.appendChild(path);
      startAngle = endAngle;
    });
    target.appendChild(svg);
    target.appendChild(legend(labels, values));
  }

  function legend(labels, values) {
    var div = document.createElement('div');
    div.className = 'yuzu-chart-legend';
    div.style.cssText = 'font:12px sans-serif;display:flex;flex-wrap:wrap;'
      + 'gap:8px 16px;margin-top:8px;';
    labels.forEach(function (l, i) {
      var item = document.createElement('span');
      item.style.cssText = 'display:inline-flex;align-items:center;gap:4px;';
      item.innerHTML = '<span style="display:inline-block;width:10px;'
        + 'height:10px;background:' + color(i) + ';border-radius:2px;"></span>'
        + escapeHtml(String(l)) + (values[i] !== undefined
          ? ' <span style="opacity:.6">(' + values[i] + ')</span>' : '');
      div.appendChild(item);
    });
    return div;
  }

  // ── Bar / Column ───────────────────────────────────────────────────────
  function renderBars(target, data, horizontal) {
    var labels = data.labels || [];
    var series = data.series || [];
    if (!series.length || !labels.length) {
      target.appendChild(emptyState('No data to plot'));
      return;
    }
    var W = 540, H = 280, padL = 60, padR = 16, padT = 12, padB = 38;
    var plotW = W - padL - padR, plotH = H - padT - padB;
    var maxV = 0;
    series.forEach(function (s) {
      (s.data || []).forEach(function (v) { if (v > maxV) maxV = v; });
    });
    if (maxV <= 0) maxV = 1;
    var groupCount = labels.length;
    var seriesCount = series.length;
    var groupSize = (horizontal ? plotH : plotW) / groupCount;
    var barSize = Math.max(2, (groupSize * 0.7) / seriesCount);
    var groupGap = groupSize * 0.15;

    var svg = svgEl('svg', {width: W, height: H, viewBox: '0 0 '+W+' '+H,
                             role: 'img', 'aria-label': data.title || 'bar chart'});

    // Axis lines
    svg.appendChild(svgEl('line', {x1: padL, y1: H - padB, x2: W - padR,
                                    y2: H - padB, stroke: '#666'}));
    svg.appendChild(svgEl('line', {x1: padL, y1: padT, x2: padL,
                                    y2: H - padB, stroke: '#666'}));

    // Y-axis ticks (5 evenly spaced)
    for (var t = 0; t <= 4; t++) {
      var y = padT + (plotH * (1 - t / 4));
      var v = (maxV * t / 4);
      svg.appendChild(svgEl('line', {x1: padL - 4, y1: y, x2: padL,
                                      y2: y, stroke: '#666'}));
      var text = svgEl('text', {x: padL - 6, y: y + 3, 'text-anchor': 'end',
                                  fill: '#999', 'font-size': 10});
      text.textContent = (v >= 1000 ? v.toFixed(0) : v.toFixed(1).replace(/\.0$/, ''));
      svg.appendChild(text);
    }

    series.forEach(function (s, si) {
      (s.data || []).forEach(function (v, gi) {
        var groupStart = (horizontal ? padT : padL) + gi * groupSize + groupGap / 2;
        var barStart = groupStart + si * barSize;
        var len = (v / maxV) * (horizontal ? plotW : plotH);
        var rect;
        if (horizontal) {
          rect = svgEl('rect', {
            x: padL, y: barStart, width: len, height: Math.max(1, barSize - 1),
            fill: color(si),
          });
        } else {
          rect = svgEl('rect', {
            x: barStart, y: H - padB - len, width: Math.max(1, barSize - 1),
            height: len, fill: color(si),
          });
        }
        rect.addEventListener('mouseenter', function (e) {
          showTip(e, '<b>' + escapeHtml(labels[gi]) + '</b><br>'
            + escapeHtml(s.name || ('series ' + si)) + ': '
            + escapeHtml(String(v)));
        });
        rect.addEventListener('mousemove', function (e) {
          showTip(e, '<b>' + escapeHtml(labels[gi]) + '</b><br>'
            + escapeHtml(s.name || ('series ' + si)) + ': '
            + escapeHtml(String(v)));
        });
        rect.addEventListener('mouseleave', hideTip);
        svg.appendChild(rect);
      });
    });

    // X-axis labels (or Y-axis if horizontal)
    labels.forEach(function (l, gi) {
      var center = (horizontal ? padT : padL) + gi * groupSize + groupSize / 2;
      var text;
      if (horizontal) {
        text = svgEl('text', {x: padL - 6, y: center + 3, 'text-anchor': 'end',
                                fill: '#bbb', 'font-size': 10});
      } else {
        text = svgEl('text', {x: center, y: H - padB + 14, 'text-anchor': 'middle',
                                fill: '#bbb', 'font-size': 10});
      }
      text.textContent = String(l).length > 12 ? String(l).slice(0, 11) + '…' : String(l);
      svg.appendChild(text);
    });

    target.appendChild(svg);
    if (series.length > 1) {
      target.appendChild(legend(series.map(function (s) { return s.name; }),
                                 series.map(function () { return undefined; })));
    }
  }

  // ── Line / Area ────────────────────────────────────────────────────────
  function renderLineLike(target, data, fillArea) {
    var xs;
    var hasDateAxis = data.x_axis === 'datetime';
    if (data.x) xs = data.x;
    else xs = (data.labels || []).map(function (_, i) { return i; });
    var series = data.series || [];
    if (!series.length || !xs.length) {
      target.appendChild(emptyState('No data to plot'));
      return;
    }
    var W = 540, H = 280, padL = 60, padR = 16, padT = 12, padB = 38;
    var plotW = W - padL - padR, plotH = H - padT - padB;

    var minX = Infinity, maxX = -Infinity, maxY = 0;
    xs.forEach(function (x) {
      if (x < minX) minX = x;
      if (x > maxX) maxX = x;
    });
    if (minX === maxX) maxX = minX + 1;
    series.forEach(function (s) {
      (s.data || []).forEach(function (v) { if (v > maxY) maxY = v; });
    });
    if (maxY <= 0) maxY = 1;

    function px(x) { return padL + ((x - minX) / (maxX - minX)) * plotW; }
    function py(y) { return padT + (1 - y / maxY) * plotH; }

    var svg = svgEl('svg', {width: W, height: H, viewBox: '0 0 '+W+' '+H,
                             role: 'img', 'aria-label': data.title || 'line chart'});

    // Axes
    svg.appendChild(svgEl('line', {x1: padL, y1: H - padB, x2: W - padR,
                                    y2: H - padB, stroke: '#666'}));
    svg.appendChild(svgEl('line', {x1: padL, y1: padT, x2: padL,
                                    y2: H - padB, stroke: '#666'}));

    for (var t = 0; t <= 4; t++) {
      var y = padT + (plotH * (1 - t / 4));
      var v = (maxY * t / 4);
      svg.appendChild(svgEl('line', {x1: padL - 4, y1: y, x2: padL,
                                      y2: y, stroke: '#666'}));
      var text = svgEl('text', {x: padL - 6, y: y + 3, 'text-anchor': 'end',
                                  fill: '#999', 'font-size': 10});
      text.textContent = (v >= 1000 ? v.toFixed(0) : v.toFixed(1).replace(/\.0$/, ''));
      svg.appendChild(text);
    }

    series.forEach(function (s, si) {
      var pts = (s.data || []).map(function (v, i) {
        return [px(xs[i]), py(v)];
      });
      if (!pts.length) return;
      if (fillArea) {
        var d = 'M' + pts.map(function (p) { return p.join(','); }).join(' L');
        d += ' L' + pts[pts.length - 1][0] + ',' + (H - padB);
        d += ' L' + pts[0][0] + ',' + (H - padB) + ' Z';
        svg.appendChild(svgEl('path', {d: d, fill: color(si),
                                        'fill-opacity': 0.25,
                                        stroke: 'none'}));
      }
      var line = svgEl('path', {
        d: 'M' + pts.map(function (p) { return p.join(','); }).join(' L'),
        fill: 'none', stroke: color(si), 'stroke-width': 2,
      });
      svg.appendChild(line);
      pts.forEach(function (p, i) {
        var dot = svgEl('circle', {cx: p[0], cy: p[1], r: 3, fill: color(si)});
        var xLabel = hasDateAxis ? new Date(xs[i] * 1000).toISOString()
                                  : String(xs[i]);
        dot.addEventListener('mouseenter', function (e) {
          showTip(e, '<b>' + escapeHtml(s.name || ('series ' + si)) + '</b><br>'
            + escapeHtml(xLabel) + ': ' + escapeHtml(String(s.data[i])));
        });
        dot.addEventListener('mousemove', function (e) {
          showTip(e, '<b>' + escapeHtml(s.name || ('series ' + si)) + '</b><br>'
            + escapeHtml(xLabel) + ': ' + escapeHtml(String(s.data[i])));
        });
        dot.addEventListener('mouseleave', hideTip);
        svg.appendChild(dot);
      });
    });

    // X-axis ticks: at most 6 evenly chosen indices so labels don't overlap.
    var xCount = xs.length;
    var step = Math.max(1, Math.floor(xCount / 6));
    for (var i = 0; i < xCount; i += step) {
      var label = hasDateAxis
        ? new Date(xs[i] * 1000).toISOString().substr(11, 5) // HH:MM
        : String(xs[i]);
      var x = px(xs[i]);
      svg.appendChild(svgEl('line', {x1: x, y1: H - padB, x2: x,
                                      y2: H - padB + 4, stroke: '#666'}));
      var text = svgEl('text', {x: x, y: H - padB + 14, 'text-anchor': 'middle',
                                  fill: '#bbb', 'font-size': 10});
      text.textContent = label;
      svg.appendChild(text);
    }

    target.appendChild(svg);
    if (series.length > 1) {
      target.appendChild(legend(series.map(function (s) { return s.name; }),
                                 series.map(function () { return undefined; })));
    }
  }

  function emptyState(msg) {
    var div = document.createElement('div');
    div.className = 'yuzu-chart-empty';
    div.style.cssText = 'padding:24px;text-align:center;color:#888;'
      + 'font:13px sans-serif;';
    div.textContent = msg;
    return div;
  }

  function render(target, data) {
    if (!target || !data) return;
    if (data.error) {
      target.appendChild(emptyState(data.error));
      return;
    }
    target.innerHTML = '';
    if (data.title) {
      var h = document.createElement('div');
      h.className = 'yuzu-chart-title';
      h.style.cssText = 'font:600 13px sans-serif;margin-bottom:6px;color:#ddd;';
      h.textContent = data.title;
      target.appendChild(h);
    }
    switch (data.chart_type) {
      case 'pie':    renderPie(target, data); break;
      case 'bar':    renderBars(target, data, true); break;
      case 'column': renderBars(target, data, false); break;
      case 'line':   renderLineLike(target, data, false); break;
      case 'area':   renderLineLike(target, data, true); break;
      default:
        target.appendChild(emptyState('Unsupported chart type: '
          + escapeHtml(String(data.chart_type))));
    }
  }

  // Auto-render any element with [data-yuzu-chart-url] — handy for HTMX
  // fragments that drop in a placeholder div and let the script tag below
  // populate it without an inline <script> block (CSP-friendly).
  function autoRender(root) {
    var els = (root || document).querySelectorAll('[data-yuzu-chart-url]');
    els.forEach(function (el) {
      if (el.dataset.yuzuChartLoaded === '1') return;
      el.dataset.yuzuChartLoaded = '1';
      fetch(el.dataset.yuzuChartUrl, {credentials: 'same-origin'})
        .then(function (r) { return r.json(); })
        .then(function (j) { render(el, (j && j.data) ? j.data : j); })
        .catch(function (err) {
          render(el, {error: 'Chart load failed: ' + err});
        });
    });
  }

  // HTMX integration: re-scan after every swap so chart cards inside HTMX
  // fragments come up automatically.
  document.addEventListener('htmx:afterSettle', function (e) {
    autoRender(e.target || document);
  });
  document.addEventListener('DOMContentLoaded', function () {
    autoRender(document);
  });

  window.YuzuCharts = {render: render, autoRender: autoRender};
})();
)JS";

} // namespace yuzu::server
