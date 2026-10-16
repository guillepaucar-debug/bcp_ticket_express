// BCP Ticket Express - API (Express + SSE + QR firmado con HMAC)
import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import QRCode from 'qrcode';
import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';
if (isProduction && (!process.env.TICKET_SECRET || process.env.TICKET_SECRET.length < 32)) {
  throw new Error('En producción debes configurar TICKET_SECRET con al menos 32 caracteres');
}
const SECRET = process.env.TICKET_SECRET || crypto.randomBytes(32).toString('hex');
const PUSH_THRESHOLD = 3; // avisar cuando restan 3 turnos
const AGENCY_ID_PATTERN = /^[A-Za-z0-9-]+$/;
const SESSION_MAX_AGE_MS = 8 * 60 * 60 * 1000;
const sessions = new Map();
const sessionCookieName = (role) => `bcp_${role}_session`;

app.use(express.json({ limit: '1mb' }));
if (isProduction) app.set('trust proxy', 1);

const getFirebaseAuth = () => {
  const serviceAccountValue = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!serviceAccountValue) throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON no está configurada');
  const serviceAccount = JSON.parse(serviceAccountValue);
  serviceAccount.private_key = serviceAccount.private_key?.replace(/\\n/g, '\n');

  const firebaseApp = getApps()[0] || initializeApp({
    credential: cert(serviceAccount),
  });
  return getAuth(firebaseApp);
};

const getFirebaseWebApiKey = () => {
  const apiKey = process.env.FIREBASE_WEB_API_KEY;
  if (!apiKey) throw new Error('FIREBASE_WEB_API_KEY no está configurada');
  return apiKey;
};

const stripSlash = (url) => url.trim().replace(/\/+$/, '');
const allowedOrigins = new Set([
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  // Firebase Hosting del proyecto (ver firebase.json)
  'https://bcpticketexpress.web.app',
  'https://bcpticketexpress.firebaseapp.com',
  // Render define esta variable automáticamente con la URL pública del servicio
  ...(process.env.RENDER_EXTERNAL_URL ? [stripSlash(process.env.RENDER_EXTERNAL_URL)] : []),
  ...(process.env.FRONTEND_ORIGINS || '')
    .split(',')
    .map(stripSlash)
    .filter(Boolean),
]);

app.use((req, res, next) => {
  const origin = req.get('Origin');
  // Si la página se sirve desde este mismo servidor, el origen siempre es válido
  const isSameOrigin = origin === `${req.protocol}://${req.get('host')}`;
  if (origin && !isSameOrigin && !allowedOrigins.has(origin)) {
    return res.status(403).json({ error: 'Origen web no autorizado. Revisa FRONTEND_ORIGINS en el backend.' });
  }
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Last-Event-ID');
    return res.sendStatus(204);
  }
  next();
});

const readSession = (req, role = null) => {
  const roles = role ? [role] : ['user', 'admin'];
  for (const sessionRole of roles) {
    const cookie = req.headers.cookie?.match(
      new RegExp(`(?:^|;\\s*)${sessionCookieName(sessionRole)}=([a-f0-9]+)`),
    )?.[1];
    if (!cookie) continue;

    const session = sessions.get(cookie);
    if (!session || session.expiresAt <= Date.now()) {
      sessions.delete(cookie);
      continue;
    }
    return session;
  }
  return null;
};

const requireRole = (role) => (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  const session = readSession(req, role);
  if (session?.role === role) {
    req.session = session;
    return next();
  }
  return res.redirect(`/login.html?role=${role}&returnTo=${encodeURIComponent(req.path)}`);
};

const requireAuthenticated = (req, res, next) => {
  const session = readSession(req);
  if (session) {
    req.session = session;
    return next();
  }
  return res.status(401).json({ error: 'Inicia sesión para continuar' });
};

const requireApiRole = (role) => (req, res, next) => {
  const session = readSession(req, role);
  if (!session) return res.status(401).json({ error: 'Inicia sesión para continuar' });
  if (session.role === role) {
    req.session = session;
    return next();
  }
  return res.status(403).json({ error: `Se requiere acceso de ${role === 'admin' ? 'administrador' : 'usuario'}` });
};

app.get('/app.html', requireRole('user'));
app.get('/ventanilla.html', requireRole('admin'));
app.get('/totem.html', requireRole('admin'));
app.use(express.static('public'));

app.post('/api/v1/auth/login', async (req, res) => {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = req.body?.password;
  if (!email || typeof password !== 'string' || !password) {
    return res.status(400).json({ error: 'Ingresa tu correo y contraseña' });
  }

  try {
    const apiKey = getFirebaseWebApiKey();
    const authResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(apiKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, returnSecureToken: true }),
      },
    );
    const authResult = await authResponse.json();
    if (!authResponse.ok) {
      const firebaseError = authResult.error?.message || String(authResponse.status);
      console.error('Firebase Authentication sign-in failed:', firebaseError);
      if (['INVALID_LOGIN_CREDENTIALS', 'EMAIL_NOT_FOUND', 'INVALID_PASSWORD', 'INVALID_EMAIL'].includes(firebaseError)) {
        return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
      }
      if (firebaseError === 'OPERATION_NOT_ALLOWED') {
        return res.status(502).json({ error: 'En Firebase Authentication no está habilitado el acceso con correo y contraseña' });
      }
      if (firebaseError === 'USER_DISABLED') {
        return res.status(403).json({ error: 'Esta cuenta está deshabilitada' });
      }
      if (firebaseError.startsWith('TOO_MANY_ATTEMPTS')) {
        return res.status(429).json({ error: 'Demasiados intentos. Espera unos minutos e inténtalo de nuevo' });
      }
      if (/API key/i.test(firebaseError)) {
        return res.status(502).json({ error: 'FIREBASE_WEB_API_KEY no es válida. Revísala en Render' });
      }
      return res.status(502).json({ error: 'No se pudo verificar la cuenta con Firebase Authentication' });
    }

    const decodedToken = await getFirebaseAuth().verifyIdToken(authResult.idToken);
    const role = decodedToken.role;
    if (!['user', 'admin'].includes(role)) {
      return res.status(403).json({ error: 'La cuenta todavía no tiene un rol asignado. Contacta al administrador.' });
    }

    const cookieName = sessionCookieName(role);
    const previousSessionId = req.headers.cookie?.match(
      new RegExp(`(?:^|;\\s*)${cookieName}=([a-f0-9]+)`),
    )?.[1];
    if (previousSessionId) sessions.delete(previousSessionId);
    const sessionId = crypto.randomBytes(32).toString('hex');
    sessions.set(sessionId, {
      uid: decodedToken.uid,
      role,
      username: decodedToken.email || email,
      expiresAt: Date.now() + SESSION_MAX_AGE_MS,
    });
    res.setHeader(
      'Set-Cookie',
      `${cookieName}=${sessionId}; Path=/; HttpOnly; SameSite=${isProduction ? 'None' : 'Lax'}; Max-Age=${SESSION_MAX_AGE_MS / 1000}${isProduction ? '; Secure' : ''}`,
    );
    res.json({ role, username: decodedToken.email || email });
  } catch (error) {
    console.error('Firebase login configuration or verification failed:', error.message);
    res.status(503).json({ error: 'No se pudo conectar con Firebase. Revisa la configuración del backend.' });
  }
});

app.post('/api/v1/admin/users', requireApiRole('admin'), async (req, res) => {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = req.body?.password;
  const displayName = typeof req.body?.displayName === 'string' ? req.body.displayName.trim() : '';

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Ingresa un correo electrónico válido' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  }
  if (!displayName || displayName.length > 80) {
    return res.status(400).json({ error: 'Ingresa un nombre de hasta 80 caracteres' });
  }

  try {
    const auth = getFirebaseAuth();
    const newUser = await auth.createUser({ email, password, displayName });
    try {
      await auth.setCustomUserClaims(newUser.uid, { role: 'user' });
    } catch (error) {
      await auth.deleteUser(newUser.uid);
      throw error;
    }
    res.status(201).json({ uid: newUser.uid, email: newUser.email, displayName: newUser.displayName, role: 'user' });
  } catch (error) {
    if (error.code === 'auth/email-already-exists') {
      return res.status(409).json({ error: 'Ya existe una cuenta con ese correo' });
    }
    console.error('Firebase user creation failed:', error.message);
    res.status(502).json({ error: 'No se pudo crear la cuenta en Firebase Authentication' });
  }
});

app.get('/api/v1/auth/me', (req, res) => {
  const requestedRole = req.query.role;
  if (requestedRole != null && !['user', 'admin'].includes(requestedRole)) {
    return res.status(400).json({ error: 'Tipo de acceso no válido' });
  }
  const session = readSession(req, requestedRole || null);
  if (!session) return res.status(401).json({ error: 'Inicia sesión para continuar' });
  res.json({ role: session.role, username: session.username });
});

app.post('/api/v1/auth/logout', (req, res) => {
  const role = req.body?.role;
  if (!['user', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Selecciona el acceso que quieres cerrar' });
  }
  const cookieName = sessionCookieName(role);
  const sessionId = req.headers.cookie?.match(
    new RegExp(`(?:^|;\\s*)${cookieName}=([a-f0-9]+)`),
  )?.[1];
  if (sessionId) sessions.delete(sessionId);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader(
    'Set-Cookie',
    `${cookieName}=; Path=/; HttpOnly; SameSite=${isProduction ? 'None' : 'Lax'}; Max-Age=0${isProduction ? '; Secure' : ''}`,
  );
  res.json({ ok: true });
});

// ---- "Base de datos" en memoria (reemplazar por PostgreSQL/Redis en producción)
const agencies = {
  '0101': {
    id: '0101',
    nombre: 'Bancom - Agencia Miraflores',
    direccion: 'Av. Paseo de la República 4870, Miraflores',
    lat: -12.1211,
    lng: -77.0297,
    last: 0,
    serving: 0,
  },
  '0102': {
    id: '0102',
    nombre: 'BCP San Isidro',
    direccion: 'Esquina de la Av. R. Rivera Navarrete con la Av. Juan de Arona, San Isidro',
    lat: -12.0977,
    lng: -77.0365,
    last: 0,
    serving: 0,
  },
  '0103': {
    id: '0103',
    nombre: 'Agencia Lima - Caja Arequipa',
    direccion: 'Jirón Carabaya 103-14 / Calle Coca N° 451-459, Cercado de Lima',
    lat: -12.0464,
    lng: -77.0306,
    last: 0,
    serving: 0,
  },
  '0104': {
    id: '0104',
    nombre: 'BCP Chacarilla',
    direccion: 'Calle Monte Grande 149, Santiago de Surco',
    lat: -12.1398,
    lng: -76.9994,
    last: 0,
    serving: 0,
  },
  '0105': {
    id: '0105',
    nombre: 'Arequipa Expreso Marvisur - Sucursal Lima Callao',
    direccion: 'Av. Elmer Faucett 435, Callao',
    lat: -12.0561,
    lng: -77.1175,
    last: 0,
    serving: 0,
  },
};
const tickets = new Map();
const listeners = new Map();

// ---- Utilidades
const sign = (id, agencia) =>
  crypto.createHmac('sha256', SECRET).update(`${id}:${agencia}`).digest('hex').slice(0, 6);

const ticketKey = (agencia, id) => `${agencia}-${id}`;

const readAgencyId = (agencyId) => {
  if (typeof agencyId !== 'string') return null;
  const normalized = agencyId.trim();
  return validateAgencyId(normalized) ? normalized : null;
};

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

const validateAgencyId = (agencyId) => typeof agencyId === 'string' && AGENCY_ID_PATTERN.test(agencyId);
const validateTicketPayload = (payload) => {
  if (typeof payload !== 'string' || !payload.trim()) return null;
  try {
    const url = new URL(payload);
    if (url.protocol !== 'bcp:') return null;
    const id = url.searchParams.get('id');
    const agencia = url.searchParams.get('agencia');
    const hash = url.searchParams.get('hash');
    if (!id || !agencia || !hash) return null;
    return { id, agencia, hash };
  } catch {
    return null;
  }
};

// ---- 1. Solicitud: sedes cercanas con estado de cola en vivo
app.get('/api/v1/agencies', requireAuthenticated, (req, res) => {
  const lat = Number.parseFloat(req.query.lat);
  const lng = Number.parseFloat(req.query.lng);
  const list = Object.values(agencies).map((a) => {
    const enCola = Math.max(0, a.last - a.serving);
    return {
      id: a.id,
      nombre: a.nombre,
      direccion: a.direccion,
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

app.get('/api/v1/agencies/:id/board', requireApiRole('admin'), (req, res) => {
  const agencyId = readAgencyId(req.params.id);
  const ag = agencyId ? agencies[agencyId] : null;
  if (!ag) return res.status(404).json({ error: 'Agencia no encontrada' });

  const agencyTickets = [...tickets.values()]
    .filter((ticket) => ticket.agencia === ag.id)
    .sort((a, b) => b.numero - a.numero);
  const current = agencyTickets.find((ticket) => ticket.estado === 'ATENDIENDO') || null;
  const history = agencyTickets
    .filter((ticket) => ticket.estado === 'ATENDIDO')
    .slice(0, 10)
    .map((ticket) => ({
      id: ticket.id,
      tramite: ticket.tramite,
      estado: ticket.estado,
      llamado: ticket.llamado,
    }));

  res.json({
    agencia: { id: ag.id, nombre: ag.nombre, direccion: ag.direccion },
    atendiendo: current ? {
      id: current.id,
      tramite: current.tramite,
      estado: current.estado,
      llamado: current.llamado,
    } : null,
    enCola: Math.max(0, ag.last - ag.serving),
    totalAtendidos: agencyTickets.filter((ticket) => ticket.estado === 'ATENDIDO').length,
    historial: history,
  });
});

// ---- 2. Generación: ticket + hash dinámico + QR
app.post('/api/v1/tickets', requireApiRole('user'), async (req, res) => {
  const { agencyId, tramite } = req.body || {};
  const normalizedAgencyId = readAgencyId(agencyId);

  if (!normalizedAgencyId || !agencies[normalizedAgencyId]) {
    return res.status(400).json({ error: 'Agencia no válida o inexistente' });
  }

  try {
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
    tickets.set(ticketKey(ag.id, id), ticket);

    const qrText = `bcp://ticket?id=${id}&agencia=${ag.id}&hash=${sign(id, ag.id)}`;
    const qr = await QRCode.toDataURL(qrText, { margin: 1, width: 280 });
    res.status(201).json({ ...view(ticket), qrText, qr });
  } catch (error) {
    console.error('Error generating ticket:', error);
    res.status(500).json({ error: 'No se pudo generar el ticket' });
  }
});

// ---- 3. Alerta push en tiempo real (Server-Sent Events)
app.get('/api/v1/tickets/:agencia/:id/events', requireApiRole('user'), (req, res) => {
  const key = ticketKey(req.params.agencia, req.params.id);
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
app.post('/api/v1/tickets/validate', requireApiRole('admin'), (req, res) => {
  const payload = req.body?.payload;
  const parsed = validateTicketPayload(payload);

  if (!parsed) return res.status(400).json({ error: 'QR inválido' });

  const { id, agencia, hash } = parsed;
  if (!id || !agencia || !hash) return res.status(400).json({ error: 'QR incompleto' });
  if (!validateAgencyId(agencia)) return res.status(400).json({ error: 'Agencia no válida' });

  const expectedAgencyId = readAgencyId(req.body?.agencyId);
  if (req.body?.agencyId != null && (!expectedAgencyId || !agencies[expectedAgencyId])) {
    return res.status(400).json({ error: 'Agencia administradora no válida' });
  }
  if (expectedAgencyId && expectedAgencyId !== agencia) {
    return res.status(409).json({ error: 'Este ticket pertenece a otra agencia' });
  }

  const t = tickets.get(ticketKey(agencia, id));
  if (!t || sign(id, agencia) !== hash) return res.status(401).json({ error: 'Ticket no válido' });
  if (t.estado === 'EN_SALA') return res.json({ ...view(t), yaValidado: true });
  if (t.estado === 'ATENDIENDO') return res.json({ ...view(t), yaLlamado: true });
  if (t.estado === 'ATENDIDO') return res.status(409).json({ error: 'Este turno ya fue atendido' });
  if (t.estado !== 'ESPERANDO') return res.status(409).json({ error: `No se puede validar un ticket en estado ${t.estado}` });

  t.estado = 'EN_SALA';
  emit(ticketKey(agencia, id), 'estado', view(t));
  res.json(view(t));
});

// ---- Ventanilla: llamar al siguiente turno y disparar alertas push
app.post('/api/v1/agencies/:id/next', requireApiRole('admin'), (req, res) => {
  const agencyId = readAgencyId(req.params.id);
  if (!agencyId || !agencies[agencyId]) return res.status(400).json({ error: 'Agencia no válida' });

  const ag = agencies[agencyId];
  if (ag.serving >= ag.last) return res.status(409).json({ error: 'No hay turnos en cola' });

  const previousTicket = [...tickets.values()].find(
    (ticket) => ticket.agencia === ag.id && ticket.numero === ag.serving,
  );
  if (previousTicket?.estado === 'ATENDIENDO') {
    previousTicket.estado = 'ATENDIDO';
    emit(ticketKey(ag.id, previousTicket.id), 'estado', view(previousTicket));
  }

  ag.serving += 1;

  for (const t of tickets.values()) {
    if (t.agencia !== ag.id) continue;
    const key = ticketKey(t.agencia, t.id);

    if (t.numero === ag.serving) {
      t.estado = 'ATENDIENDO';
      t.llamado = Date.now();
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

  res.json({
    agencia: ag.id,
    turno: `T${String(ag.serving).padStart(3, '0')}`,
    atendiendo: ag.serving,
    enCola: ag.last - ag.serving,
  });
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: `Ruta API no encontrada: ${req.method} ${req.originalUrl}` });
});

app.use((error, _req, res, _next) => {
  console.error('Unhandled error:', error);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Error interno del servidor' });
});

app.listen(PORT, () => console.log(`BCP Ticket Express → http://localhost:${PORT}`));
