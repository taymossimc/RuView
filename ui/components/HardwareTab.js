// Hardware Tab Component
//
// Renders what the connected sensing-server reports about the capture
// hardware: source label, per-node radio header (frequency, noise floor,
// PPDU type, antennas), subcarrier count, measured frame rate, RSSI and
// the latest amplitude vector. Nothing here is assumed or simulated; a
// field the server does not report is shown as "not reported".

import { sensingService } from '../services/sensing.service.js';

const NOT_REPORTED = 'not reported';

export class HardwareTab {
  constructor(containerElement) {
    this.container = containerElement;
    this._unsubData = null;
    this._unsubState = null;
    this._lastData = null;
    this._state = sensingService.state;
  }

  init() {
    this._sourceGrid = this.container.querySelector('#hw-source-grid');
    this._nodesEl = this.container.querySelector('#hw-nodes');
    this._unsubState = sensingService.onStateChange((state) => {
      this._state = state;
      this._render();
    });
    this._unsubData = sensingService.onData((data) => {
      this._lastData = data;
      this._render();
    });
    this._render();
  }

  // ---- rendering -----------------------------------------------------------

  _render() {
    if (!this._sourceGrid || !this._nodesEl) return;
    const data = this._lastData;
    const nodes = (data && Array.isArray(data.nodes)) ? data.nodes : [];
    const nodeFeatures = (data && Array.isArray(data.node_features)) ? data.node_features : [];
    const featById = new Map(nodeFeatures.map((nf) => [nf.node_id, nf]));

    this._renderSource(data, nodes, nodeFeatures);
    this._renderNodes(nodes, featById);
  }

  _renderSource(data, nodes, nodeFeatures) {
    const connected = this._state === 'connected';
    const raw = sensingService.serverSource;
    const items = [];

    items.push(['Connection', connected ? 'connected' : this._state]);
    items.push(['Source (server label)', raw ? `${sensingService.liveSourceName} (${raw})` : NOT_REPORTED]);
    items.push(['Data provenance', this._provenance(data)]);
    items.push(['Active nodes', data ? String(nodes.length) : NOT_REPORTED]);

    const freqs = uniq(nodes.map((n) => n.radio && n.radio.freq_mhz).filter(isNum));
    items.push(['Centre frequency', freqs.length ? freqs.map((f) => `${f} MHz`).join(', ') : NOT_REPORTED]);

    const subs = uniq(nodes.map((n) => n.subcarrier_count).filter((v) => isNum(v) && v > 0));
    items.push(['Subcarriers per node', subs.length ? subs.join(', ') : NOT_REPORTED]);

    const rates = nodeFeatures.map((nf) => nf.frame_rate_hz).filter(isNum);
    items.push(['Frame rate per node (measured)', rates.length ? `${fmtRange(rates, 1)} Hz` : NOT_REPORTED]);

    const noise = uniq(nodes.map((n) => n.radio && n.radio.noise_floor_dbm).filter(isNum));
    items.push(['Noise floor', noise.length ? noise.map((v) => `${v} dBm`).join(', ') : NOT_REPORTED]);

    const ppdu = uniq(nodes.map((n) => n.radio && n.radio.ppdu_type).filter(Boolean));
    items.push(['PPDU type', ppdu.length ? ppdu.join(', ') : NOT_REPORTED]);

    const ants = uniq(nodes.map((n) => n.radio && n.radio.n_antennas).filter(isNum));
    items.push(['Antennas per node frame', ants.length ? ants.join(', ') : NOT_REPORTED]);

    const configured = nodes.filter((n) => n.position_configured).length;
    items.push(['Node positions', nodes.length
      ? (configured ? `${configured}/${nodes.length} configured (--node-positions)` : 'none configured (server placeholder)')
      : NOT_REPORTED]);

    this._sourceGrid.replaceChildren(...items.map(([label, value]) => configItem(label, value)));
  }

  _provenance(data) {
    if (!data) return 'no data received yet';
    const ds = sensingService.dataSource;
    if (ds === 'simulated') return 'SIMULATED (client-side generator)';
    if (ds === 'unreachable') return 'STALE (server unreachable)';
    if (ds === 'reconnecting') return 'STALE (reconnecting)';
    const src = String(data.source || '');
    if (src === 'simulated' || src === 'synthetic') return 'SIMULATED (server)';
    return 'live frames from the server';
  }

  _renderNodes(nodes, featById) {
    if (!nodes.length) {
      const p = document.createElement('p');
      p.className = 'help-text';
      p.textContent = this._lastData ? 'The server reports no active CSI nodes.' : 'Waiting for the first sensing update…';
      this._nodesEl.replaceChildren(p);
      return;
    }
    const sorted = [...nodes].sort((a, b) => a.node_id - b.node_id);
    const cards = sorted.map((n) => this._nodeCard(n, featById.get(n.node_id)));
    this._nodesEl.replaceChildren(...cards);
  }

  _nodeCard(n, nf) {
    const card = document.createElement('div');
    card.className = 'hw-node';

    const head = document.createElement('div');
    head.className = 'hw-node-head';
    const title = document.createElement('span');
    title.className = 'hw-node-id';
    title.textContent = `node ${n.node_id}`;
    const state = document.createElement('span');
    const level = n.node_inference ? n.node_inference.classification : null;
    state.className = `hw-node-state hw-level-${(level || 'unknown').replace(/[^a-z_]/g, '')}`;
    state.textContent = level || 'no inference';
    head.append(title, state);
    card.appendChild(head);

    const rows = [
      ['RSSI', isNum(n.rssi_dbm) ? `${n.rssi_dbm.toFixed(1)} dBm` : NOT_REPORTED],
      ['Subcarriers', n.subcarrier_count > 0 ? String(n.subcarrier_count) : NOT_REPORTED],
      ['Frame rate', nf && isNum(nf.frame_rate_hz) ? `${nf.frame_rate_hz.toFixed(2)} Hz` : NOT_REPORTED],
      ['Frequency', n.radio && isNum(n.radio.freq_mhz) ? `${n.radio.freq_mhz} MHz` : NOT_REPORTED],
      ['Noise floor', n.radio && isNum(n.radio.noise_floor_dbm) ? `${n.radio.noise_floor_dbm} dBm` : NOT_REPORTED],
      ['Position', Array.isArray(n.position)
        ? `${n.position.map((v) => Number(v).toFixed(1)).join(', ')} m ${n.position_configured ? '(configured)' : '(placeholder, not measured)'}`
        : NOT_REPORTED],
    ];
    if (nf && nf.features) {
      rows.push(['Variance / motion band', `${fmt(nf.features.variance)} / ${fmt(nf.features.motion_band_power)}`]);
    }
    const dl = document.createElement('dl');
    dl.className = 'hw-node-rows';
    for (const [k, v] of rows) {
      const dt = document.createElement('dt');
      dt.textContent = k;
      const dd = document.createElement('dd');
      dd.textContent = v;
      dl.append(dt, dd);
    }
    card.appendChild(dl);

    const amps = Array.isArray(n.amplitude) ? n.amplitude.filter(isNum) : [];
    const canvas = document.createElement('canvas');
    canvas.className = 'hw-node-amp';
    canvas.width = 260;
    canvas.height = 56;
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', amps.length
      ? `Amplitude of ${amps.length} subcarriers for node ${n.node_id}`
      : `No amplitude data for node ${n.node_id}`);
    card.appendChild(canvas);
    drawAmplitude(canvas, amps);
    return card;
  }

  dispose() {
    if (this._unsubData) this._unsubData();
    if (this._unsubState) this._unsubState();
    this._unsubData = this._unsubState = null;
  }
}

// ---- helpers ---------------------------------------------------------------

function isNum(v) {
  return typeof v === 'number' && Number.isFinite(v);
}

function uniq(arr) {
  return [...new Set(arr)];
}

function fmt(v) {
  return isNum(v) ? v.toFixed(1) : NOT_REPORTED;
}

function fmtRange(values, digits) {
  const lo = Math.min(...values);
  const hi = Math.max(...values);
  return Math.abs(hi - lo) < 0.05 ? lo.toFixed(digits) : `${lo.toFixed(digits)}–${hi.toFixed(digits)}`;
}

function configItem(label, value) {
  const item = document.createElement('div');
  item.className = 'config-item';
  const l = document.createElement('label');
  l.textContent = label;
  const v = document.createElement('div');
  v.className = 'config-value';
  v.textContent = value;
  item.append(l, v);
  return item;
}

function drawAmplitude(canvas, amps) {
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const { width: w, height: h } = canvas;
  ctx.clearRect(0, 0, w, h);
  if (!amps.length) {
    ctx.fillStyle = 'rgba(128,128,128,0.6)';
    ctx.font = '11px sans-serif';
    ctx.fillText('no amplitude data', 6, h / 2 + 4);
    return;
  }
  const max = Math.max(...amps, 1e-9);
  const barW = w / amps.length;
  ctx.fillStyle = '#1FB8CD';
  amps.forEach((a, i) => {
    const bh = Math.max(1, (a / max) * (h - 4));
    ctx.fillRect(i * barW, h - bh, Math.max(1, barW - 1), bh);
  });
  const label = `max |H| ${max.toFixed(0)} · ${amps.length} tones`;
  ctx.font = '10px sans-serif';
  const tw = ctx.measureText(label).width;
  ctx.fillStyle = 'rgba(255,255,255,0.75)';
  ctx.fillRect(2, 1, tw + 6, 12);
  ctx.fillStyle = '#333';
  ctx.fillText(label, 5, 10);
}
