// BCP Ticket Express - API (Express + SSE + QR firmado con HMAC)
import express from 'express';
import crypto from 'crypto';
import QRCode from 'qrcode';

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const SECRET = process.env.TICKET_SECRET || 'cambia-este-secreto';
const PUSH_THRESHOLD = 3; // avisar cuando restan 3 turnos

app.use(express.json({ limit: '1mb' }));
app.use(express.static('public'));

// ---- "Base de datos" en memoria (reemplazar por PostgreSQL/Redis en producción)
const agencies = {
  '0101': { id: '0101', nombre: 'Agencia Miraflores', lat: -12.1211, lng: -77.0297, last: 0, serving: 0 },
  '0102': { id: '0102', nombre: 'Agencia San Isidro', lat: -12.0977, lng: -77.0365, last: 0, serving: 0 },
  '0103': { id: '0103', nombre: 'Agencia Centro de Lima', lat: -12.0464, lng: -77.0306, last: 0, serving: 0 },
};
const tickets = new Map();
const listeners = new Map();

// ---- Utilidades
const sign = (id, agencia) =>
  crypto.createHmac('sha256', SECRET).update(`${id}:${agencia}`).digest('hex').slice(0, 6);

const km = (a, b, c, d) => {
  const r = (x) => (x * Math.PI) / 180;
  const h = Math.sin(r(c - a) / 2) ** 2 +
    Math.cos(r(a)) * Math.cos(r(c)) * Math.sin(r(d - b) / 2) ** 2;
  return 6371 * 2 * Math.asin(Math.sqrt(h));
};

const emit = (key, event, data) => {
  const subscribers = listeners.get(key) || new Set();
  for (const res of subscribers) {
    if (!res.writableEnded) {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    }
  }
};

const view = (t) => ({
  id: t.id,
  agencia: t.agencia,
  tramite: t.tramite,
  estado: t.estado,
  turnosPrevios: Math.max(0, (t.numero ?? 0) - (agencies[t.agencia]?.serving ?? 0) - 1),
});

const validateAgencyId = (agencyId) => typeof agencyId === 'string' && /^[A-Za-z0-9-]+$/.test(agencyId);
const validateTicketPayload = (payload) => {
  if (typeof payload !== 'string' || !payload.trim()) return null;
  try {
    const url = new URL(payload);
    if (url.protocol !== 'bcp:') return null;
    return {
      id: url.searchParams.get('id'),
      agencia: url.searchParams.get('agencia'),
      hash: url.searchParams.get('hash'),
    };
  } catch {
    return null;
  }
};

// ---- 1. Solicitud: sedes cercanas con estado de cola en vivo
app.get('/api/v1/agencies', (req, res) => {
  const lat = Number.parseFloat(req.query.lat);
  const lng = Number.parseFloat(req.query.lng);
  const list = Object.values(agencies).map((a) => {
    const enCola = Math.max(0, a.last - a.serving);
    return {
      id: a.id,
      nombre: a.nombre,
      enCola,
      tiempoEstimadoMin: enCola * 4,
      distanciaKm: Number.isFinite(lat) && Number.isFinite(lng) ? +km(lat, lng, a.lat, a.lng).toFixed(1) : null,
    };
  });
  list.sort((x, y) => (x.distanciaKm ?? Number.MAX_SAFE_INTEGER) - (y.distanciaKm ?? Number.MAX_SAFE_INTEGER));
  res.json(list);
});

app.get('/api/v1/health', (_req, res) => {
  res.json({ ok: true, uptime: process.uptime(), port: PORT });
});

// ---- 2. Generación: ticket + hash dinámico + QR
app.post('/api/v1/tickets', async (req, res) => {
  const { agencyId, tramite } = req.body || {};
  const normalizedAgencyId = typeof agencyId === 'string' ? agencyId.trim() : '';

  if (!validateAgencyId(normalizedAgencyId) || !agencies[normalizedAgencyId]) {
    return res.status(400).json({ error: 'Agencia no válida o inexistente' });
  }

  const ag = agencies[normalizedAgencyId];
  ag.last += 1;
  const id = `T${String(ag.last).padStart(3, '0')}`;
  const descripcion = typeof tramite === 'string' && tramite.trim() ? tramite.trim() : 'General';
  const ticket = {
    id,
    numero: ag.last,
    agencia: ag.id,
    tramite: descripcion,
    estado: 'ESPERANDO',
    notificado: false,
    creado: Date.now(),
  };
  tickets.set(`${ag.id}-${id}`, ticket);

  const qrText = `bcp://ticket?id=${id}&agencia=${ag.id}&hash=${sign(id, ag.id)}`;
  const qr = await QRCode.toDataURL(qrText, { margin: 1, width: 280 });
  res.status(201).json({ ...view(ticket), qrText, qr });
});

// ---- 3. Alerta push en tiempo real (Server-Sent Events)
app.get('/api/v1/tickets/:agencia/:id/events', (req, res) => {
  const key = `${req.params.agencia}-${req.params.id}`;
  const t = tickets.get(key);
  if (!t) return res.sendStatus(404);

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();
  res.write(`event: estado\ndata: ${JSON.stringify(view(t))}\n\n`);

  if (!listeners.has(key)) listeners.set(key, new Set());
  listeners.get(key).add(res);
  req.on('close', () => listeners.get(key)?.delete(res));
});

// ---- 4/5. Lectura en tótem y confirmación "En Sala"
app.post('/api/v1/tickets/validate', (req, res) => {
  const payload = req.body?.payload;
  const parsed = validateTicketPayload(payload);

  if (!parsed) return res.status(400).json({ error: 'QR inválido' });

  const { id, agencia, hash } = parsed;
  if (!id || !agencia || !hash) return res.status(400).json({ error: 'QR incompleto' });

  const t = tickets.get(`${agencia}-${id}`);
  if (!t || sign(id, agencia) !== hash) return res.status(401).json({ error: 'Ticket no válido' });
  if (t.estado !== 'ESPERANDO') return res.status(409).json({ error: `Ticket ya está ${t.estado}` });

  t.estado = 'EN_SALA';
  emit(`${agencia}-${id}`, 'estado', view(t));
  res.json(view(t));
});

// ---- Ventanilla: llamar al siguiente turno y disparar alertas push
app.post('/api/v1/agencies/:id/next', (req, res) => {
  const ag = agencies[req.params.id];
  if (!ag) return res.sendStatus(404);
  if (ag.serving >= ag.last) return res.status(409).json({ error: 'No hay turnos en cola' });

  ag.serving += 1;

  for (const t of tickets.values()) {
    if (t.agencia !== ag.id) continue;
    const key = `${t.agencia}-${t.id}`;

    if (t.numero === ag.serving) {
      t.estado = 'ATENDIENDO';
      emit(key, 'estado', view(t));
    } else if (t.numero > ag.serving) {
      const previos = t.numero - ag.serving - 1;
      emit(key, 'estado', view(t));
      if (previos <= PUSH_THRESHOLD && !t.notificado) {
        t.notificado = true;
        emit(key, 'push', { titulo: 'BCP Ticket Express', mensaje: 'Acércate a la agencia', restan: previos });
      }
    }
  }

  res.json({ agencia: ag.id, atendiendo: ag.serving, enCola: ag.last - ag.serving });
});

app.listen(PORT, () => console.log(`BCP Ticket Express → http://localhost:${PORT}`));
