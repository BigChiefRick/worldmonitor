/**
 * oref-alerts.js
 *
 * Replacement for the Railway-relay-based OREF handler.
 * Polls api.tzevaadom.co.il directly — no residential proxy,
 * no Railway relay, no WS_RELAY_URL required.
 *
 * Endpoints:
 *   GET /api/oref-alerts                  → live alerts  (OrefAlertsResponse)
 *   GET /api/oref-alerts?endpoint=history → 24h history  (OrefHistoryResponse)
 *
 * tzevaadom /notifications schema:
 *   [{
 *     notificationId: string,
 *     time: number (unix seconds),
 *     threat: number,
 *     isDrill: boolean,
 *     cities: string[]   ← Hebrew city names
 *   }]
 */
import { getCorsHeaders, isDisallowedOrigin } from './_cors.js';

export const config = { runtime: 'edge' };

const TZEVAADOM_BASE    = 'https://api.tzevaadom.co.il';
const TZEVAADOM_LIVE    = `${TZEVAADOM_BASE}/notifications`;
const TZEVAADOM_HISTORY = `${TZEVAADOM_BASE}/notifications/history`;

const THREAT_MAP = {
  0: { cat: 'missiles',       title: 'Rocket and missile fire' },
  1: { cat: 'uav',            title: 'Hostile aircraft intrusion' },
  2: { cat: 'infiltration',   title: 'Suspected hostile infiltration' },
  3: { cat: 'earthquake',     title: 'Earthquake' },
  4: { cat: 'tsunami',        title: 'Tsunami' },
  5: { cat: 'hazmat',         title: 'Hazardous materials' },
  6: { cat: 'radiological',   title: 'Radiological event' },
  7: { cat: 'unconventional', title: 'Non-conventional threat' },
};

function threatInfo(code) {
  return THREAT_MAP[code] ?? { cat: 'alert', title: 'Alert' };
}

function toOrefAlert(n) {
  const { cat, title } = threatInfo(n.threat);
  const alertDate = new Date((n.time ?? 0) * 1000).toISOString();
  return {
    id:        n.notificationId ?? String(n.time),
    cat,
    title:     n.isDrill ? `[DRILL] ${title}` : title,
    data:      Array.isArray(n.cities) ? n.cities : [],
    desc:      n.isDrill ? 'This is a drill' : title,
    alertDate,
  };
}

async function fetchWithTimeout(url, opts = {}, ms = 10_000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

function count24h(notifications) {
  const cutoff = Date.now() / 1000 - 86_400;
  return notifications.filter(n => (n.time ?? 0) >= cutoff).length;
}

// Group flat notification list into wave buckets (≤30s apart = same wave)
function groupIntoWaves(notifications) {
  if (!notifications.length) return [];
  const sorted = [...notifications].sort((a, b) => a.time - b.time);
  const waves = [];
  let current = [sorted[0]];
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i].time - sorted[i - 1].time <= 30) {
      current.push(sorted[i]);
    } else {
      waves.push(current);
      current = [sorted[i]];
    }
  }
  waves.push(current);
  return waves.reverse().map(wave => ({
    timestamp: new Date(wave[0].time * 1000).toISOString(),
    alerts: wave.map(toOrefAlert),
  }));
}

async function handleHistory(corsHeaders) {
  let raw;
  try {
    const res = await fetchWithTimeout(TZEVAADOM_HISTORY, {
      headers: { Accept: 'application/json', 'User-Agent': 'WorldMonitor/1.0' },
    }, 12_000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    raw = await res.json();
  } catch {
    // history endpoint may not exist — fall back to live
    try {
      const res2 = await fetchWithTimeout(TZEVAADOM_LIVE, {
        headers: { Accept: 'application/json', 'User-Agent': 'WorldMonitor/1.0' },
      }, 10_000);
      raw = res2.ok ? await res2.json() : [];
    } catch {
      raw = [];
    }
  }
  const notifications = Array.isArray(raw) ? raw : [];
  return new Response(JSON.stringify({
    configured: true,
    history: groupIntoWaves(notifications),
    historyCount24h: count24h(notifications),
    timestamp: new Date().toISOString(),
  }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=60, s-maxage=300, stale-while-revalidate=120',
      ...corsHeaders,
    },
  });
}

async function handleAlerts(corsHeaders) {
  let raw;
  try {
    const res = await fetchWithTimeout(TZEVAADOM_LIVE, {
      headers: { Accept: 'application/json', 'User-Agent': 'WorldMonitor/1.0' },
    }, 10_000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    raw = await res.json();
  } catch (err) {
    // Service reachable but temporarily unavailable — configured:true so UI
    // shows "0 alerts" rather than "Sirens service not configured"
    return new Response(JSON.stringify({
      configured: true,
      alerts: [],
      historyCount24h: 0,
      timestamp: new Date().toISOString(),
      error: String(err),
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders },
    });
  }
  const notifications = Array.isArray(raw) ? raw : [];
  return new Response(JSON.stringify({
    configured: true,
    alerts: notifications.map(toOrefAlert),
    historyCount24h: count24h(notifications),
    totalHistoryCount: notifications.length,
    timestamp: new Date().toISOString(),
  }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=8, s-maxage=15, stale-while-revalidate=30',
      ...corsHeaders,
    },
  });
}

export default async function handler(req) {
  const corsHeaders = getCorsHeaders(req, 'GET, OPTIONS');
  if (isDisallowedOrigin(req)) {
    return new Response(JSON.stringify({ error: 'Origin not allowed' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });
  if (req.method !== 'GET') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), {
      status: 405,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
    });
  }
  const endpoint = new URL(req.url).searchParams.get('endpoint');
  return endpoint === 'history' ? handleHistory(corsHeaders) : handleAlerts(corsHeaders);
}
