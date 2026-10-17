// BCP Ticket Express - API (Express + SSE + QR firmado con HMAC)
import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import QRCode from 'qrcode';
import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { FieldValue, getFirestore } from 'firebase-admin/firestore';

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === 'production';
if (isProduction && (!process.env.TICKET_SECRET || process.env.TICKET_SECRET.length < 32)) {
  throw new Error('En producción debes configurar TICKET_SECRET con al menos 32 caracteres');
}
const SECRET = process.env.TICKET_SECRET || crypto.randomBytes(32).toString('hex');
const PUSH_THRESHOLD = 3; // avisar cuando restan 3 turnos
const AGENCY_ID_PATTERN = /^[A-Za-z0-9-]+$/;
const ATTENTION_TYPES = ['plataforma', 'ventanilla'];
const readAttentionType = (attentionType) =>
  typeof attentionType === 'string' && ATTENTION_TYPES.includes(attentionType.trim().toLowerCase())
    ? attentionType.trim().toLowerCase()
    : null;
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

const getDniHash = (dni) => {
  const secret = process.env.DNI_HASH_SECRET || SECRET;
  if (secret.length < 32) {
    throw new Error('La clave para proteger el DNI debe tener al menos 32 caracteres');
  }
  const dniKey = crypto.createHmac('sha256', secret)
    .update('bcp-ticket-express:dni-registry:v1')
    .digest();
  return crypto.createHmac('sha256', dniKey).update(dni).digest('hex');
};

const sendVerificationEmail = async (idToken, apiKey = getFirebaseWebApiKey()) => {
  const response = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${encodeURIComponent(apiKey)}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ requestType: 'VERIFY_EMAIL', idToken }),
    },
  );
  const result = await response.json();
  if (!response.ok) {
    console.error('Firebase email verification request failed:', result.error?.message || response.status);
    throw new Error('No se pudo enviar el correo de verificación');
  }
};

const createUserWithDni = async ({ email, password, displayName, dni }) => {
  const dniHash = getDniHash(dni);
  const apiKey = getFirebaseWebApiKey();
  const auth = getFirebaseAuth();
  const db = getFirestore(auth.app);
  const dniRef = db.collection('dni_registry').doc(dniHash);
  let newUser;
  let profileRef;

  try {
    newUser = await auth.createUser({ email, password, displayName });
    profileRef = db.collection('users').doc(newUser.uid);
    await auth.setCustomUserClaims(newUser.uid, { role: 'user' });
    await db.runTransaction(async (transaction) => {
      const existingDni = await transaction.get(dniRef);
      if (existingDni.exists) {
        const error = new Error('Este DNI ya está asociado a una cuenta');
        error.code = 'app/dni-already-registered';
        throw error;
      }
      transaction.create(dniRef, {
        uid: newUser.uid,
        createdAt: FieldValue.serverTimestamp(),
      });
      transaction.create(profileRef, {
        uid: newUser.uid,
        displayName: newUser.displayName,
        email: newUser.email,
        dni,
        createdAt: FieldValue.serverTimestamp(),
      });
    });
  } catch (error) {
    if (newUser) {
      try {
        await db.runTransaction(async (transaction) => {
          const registeredDni = await transaction.get(dniRef);
          const registeredProfile = await transaction.get(profileRef);
          if (registeredDni.data()?.uid === newUser.uid) transaction.delete(dniRef);
          if (registeredProfile.data()?.uid === newUser.uid) transaction.delete(profileRef);
        });
      } catch (cleanupError) {
        console.error('Could not release DNI reservation after account creation failed:', cleanupError.message);
      }
      try {
        await auth.deleteUser(newUser.uid);
      } catch (cleanupError) {
        console.error('Could not delete incomplete Firebase account:', cleanupError.message);
      }
    }
    if (newUser && error.code !== 'app/dni-already-registered') {
      console.error('Could not save user profile in Firestore:', error.message);
      error.code = 'app/profile-save-failed';
    }
    throw error;
  }

  let verificationEmailSent = true;
  try {
    const signInResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(apiKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, returnSecureToken: true }),
      },
    );
    const signInResult = await signInResponse.json();
    if (!signInResponse.ok || typeof signInResult.idToken !== 'string') {
      throw new Error(signInResult.error?.message || `HTTP ${signInResponse.status}`);
    }
    await sendVerificationEmail(signInResult.idToken, apiKey);
  } catch (error) {
    verificationEmailSent = false;
    console.error(`User profile saved, but verification email was not sent for uid ${newUser.uid}:`, error.message);
  }
  return { user: newUser, verificationEmailSent };
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
    if (role === 'user') {
      const dni = typeof req.body?.dni === 'string' ? req.body.dni.trim() : '';
      if (!/^\d{8}$/.test(dni)) {
        return res.status(400).json({ error: 'Ingresa el DNI de 8 dígitos asociado a tu cuenta' });
      }
      const dniHash = getDniHash(dni);
      const dniRecord = await getFirestore(getFirebaseAuth().app)
        .collection('dni_registry')
        .doc(dniHash)
        .get();
      if (dniRecord.data()?.uid !== decodedToken.uid) {
        return res.status(401).json({ error: 'El DNI no coincide con el correo asociado a esta cuenta' });
      }
    }
    if (role === 'user' && !decodedToken.email_verified) {
      try {
        await sendVerificationEmail(authResult.idToken);
      } catch (error) {
        console.error('Could not resend verification email:', error.message);
        return res.status(502).json({ error: 'No pudimos enviar el correo de verificación. Inténtalo de nuevo más tarde.' });
      }
      return res.status(403).json({ error: 'Verifica tu correo con el enlace que te enviamos para poder iniciar sesión.' });
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
    if (/clave para proteger el DNI/i.test(error.message)) {
      return res.status(503).json({ error: 'No se puede validar el DNI. Configura una clave estable de al menos 32 caracteres en el servidor.' });
    }
    res.status(503).json({ error: 'No se pudo conectar con Firebase. Revisa la configuración del backend.' });
  }
});

app.post('/api/v1/auth/register', async (req, res) => {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = req.body?.password;
  const displayName = typeof req.body?.displayName === 'string' ? req.body.displayName.trim() : '';
  const dni = typeof req.body?.dni === 'string' ? req.body.dni.trim() : '';

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Ingresa un correo electrónico válido' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  }
  if (!displayName || displayName.length > 80) {
    return res.status(400).json({ error: 'Ingresa un nombre de hasta 80 caracteres' });
  }
  if (!/^\d{8}$/.test(dni)) {
    return res.status(400).json({ error: 'Ingresa un DNI válido de 8 dígitos' });
  }

  try {
    const { user, verificationEmailSent } = await createUserWithDni({ email, password, displayName, dni });
    res.status(201).json({
      email: user.email,
      displayName: user.displayName,
      role: 'user',
      verificationEmailSent,
    });
  } catch (error) {
    if (error.code === 'auth/email-already-exists') {
      return res.status(409).json({ error: 'Ya existe una cuenta con ese correo' });
    }
    if (error.code === 'app/dni-already-registered') {
      return res.status(409).json({ error: error.message });
    }
    if (error.code === 'app/profile-save-failed') {
      return res.status(503).json({ error: 'No se pudo guardar el perfil en Firestore. Revisa que Firestore esté habilitado y que las credenciales del servidor pertenezcan al proyecto correcto.' });
    }
    console.error('Firebase self-registration failed:', error.message);
    if (/clave para proteger el DNI/i.test(error.message)) {
      return res.status(503).json({ error: 'El registro no está disponible. Revisa la clave para proteger el DNI en el servidor.' });
    }
    res.status(502).json({ error: 'No se pudo completar el registro. Revisa la configuración de Firebase Authentication y Cloud Firestore.' });
  }
});

app.post('/api/v1/admin/users', requireApiRole('admin'), async (req, res) => {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  const password = req.body?.password;
  const displayName = typeof req.body?.displayName === 'string' ? req.body.displayName.trim() : '';
  const dni = typeof req.body?.dni === 'string' ? req.body.dni.trim() : '';

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Ingresa un correo electrónico válido' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres' });
  }
  if (!displayName || displayName.length > 80) {
    return res.status(400).json({ error: 'Ingresa un nombre de hasta 80 caracteres' });
  }
  if (!/^\d{8}$/.test(dni)) {
    return res.status(400).json({ error: 'Ingresa un DNI válido de 8 dígitos' });
  }

  try {
    const { user, verificationEmailSent } = await createUserWithDni({ email, password, displayName, dni });
    res.status(201).json({
      uid: user.uid,
      email: user.email,
      displayName: user.displayName,
      role: 'user',
      verificationEmailSent,
    });
  } catch (error) {
    if (error.code === 'auth/email-already-exists') {
      return res.status(409).json({ error: 'Ya existe una cuenta con ese correo' });
    }
    if (error.code === 'app/dni-already-registered') {
      return res.status(409).json({ error: error.message });
    }
    if (error.code === 'app/profile-save-failed') {
      return res.status(503).json({ error: 'No se pudo guardar el perfil en Firestore. Revisa que Firestore esté habilitado y que las credenciales del servidor pertenezcan al proyecto correcto.' });
    }
    console.error('Firebase user creation failed:', error.message);
    if (/clave para proteger el DNI/i.test(error.message)) {
      return res.status(503).json({ error: 'El registro no está disponible. Revisa la clave para proteger el DNI en el servidor.' });
    }
    res.status(502).json({ error: 'No se pudo completar el registro. Revisa la configuración de Firebase Authentication y Cloud Firestore.' });
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
    horario: { lunesViernes: { apertura: '09:00', cierre: '18:00' }, sabado: { apertura: '09:00', cierre: '23:30' } },
    last: 0,
  },
  '0102': {
    id: '0102',
    nombre: 'BCP San Isidro',
    direccion: 'Esquina de la Av. R. Rivera Navarrete con la Av. Juan de Arona, San Isidro',
    lat: -12.0977,
    lng: -77.0365,
    horario: { lunesViernes: { apertura: '09:00', cierre: '18:00' }, sabado: { apertura: '09:00', cierre: '23:30' } },
    last: 0,
  },
  '0103': {
    id: '0103',
    nombre: 'Agencia Lima - Caja Arequipa',
    direccion: 'Jirón Carabaya 103-14 / Calle Coca N° 451-459, Cercado de Lima',
    lat: -12.0464,
    lng: -77.0306,
    horario: { lunesViernes: { apertura: '09:00', cierre: '18:00' }, sabado: { apertura: '09:00', cierre: '23:30' } },
    last: 0,
  },
  '0104': {
    id: '0104',
    nombre: 'BCP Chacarilla',
    direccion: 'Calle Monte Grande 149, Santiago de Surco',
    lat: -12.1398,
    lng: -76.9994,
    horario: { lunesViernes: { apertura: '09:00', cierre: '18:00' }, sabado: { apertura: '09:00', cierre: '23:30' } },
    last: 0,
  },
  '0105': {
    id: '0105',
    nombre: 'Arequipa Expreso Marvisur - Sucursal Lima Callao',
    direccion: 'Av. Elmer Faucett 435, Callao',
    lat: -12.0561,
    lng: -77.1175,
    horario: { lunesViernes: { apertura: '09:00', cierre: '18:00' }, sabado: { apertura: '09:00', cierre: '23:30' } },
    last: 0,
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

const limaParts = (date = new Date()) => Object.fromEntries(
  new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Lima',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date)
    .filter((part) => part.type !== 'literal')
    .map(({ type, value }) => [type, value]),
);

const dateWithinBookingWindow = (date) => {
  if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return false;
  const [year, month, day] = date.split('-').map(Number);
  const parsed = new Date(Date.UTC(year, month - 1, day));
  if (parsed.toISOString().slice(0, 10) !== date) return false;
  const todayParts = limaParts();
  const today = `${todayParts.year}-${todayParts.month}-${todayParts.day}`;
  const latest = new Date(`${today}T00:00:00Z`);
  latest.setUTCDate(latest.getUTCDate() + 14);
  return date >= today && date <= latest.toISOString().slice(0, 10);
};

const appointmentTimestamp = (date, time) => Date.parse(`${date}T${time}:00-05:00`);

const getSlotsForDate = (agency, date, attentionType) => {
  if (!dateWithinBookingWindow(date)) return null;
  const weekday = new Date(`${date}T00:00:00Z`).getUTCDay();
  const schedule = weekday >= 1 && weekday <= 5
    ? agency.horario.lunesViernes
    : weekday === 6
      ? agency.horario.sabado
      : null;
  if (!schedule) return [];

  const opening = Number(schedule.apertura.slice(0, 2)) * 60 + Number(schedule.apertura.slice(3, 5));
  const closing = Number(schedule.cierre.slice(0, 2)) * 60 + Number(schedule.cierre.slice(3, 5));
  const bookedSlots = new Set([...tickets.values()]
    .filter((ticket) => ticket.agencia === agency.id
      && ticket.tipoAtencion === attentionType
      && ticket.fechaCita === date
      && ticket.estado !== 'ATENDIDO')
    .map((ticket) => ticket.horaCita));
  const now = Date.now();
  const slots = [];
  for (let minute = opening; minute + 30 <= closing; minute += 30) {
    const time = `${String(Math.floor(minute / 60)).padStart(2, '0')}:${String(minute % 60).padStart(2, '0')}`;
    slots.push({
      hora: time,
      disponible: appointmentTimestamp(date, time) > now && !bookedSlots.has(time),
    });
  }
  return slots;
};

const getAgencyHours = (agency) => ({
  lunesViernes: `${agency.horario.lunesViernes.apertura}–${agency.horario.lunesViernes.cierre}`,
  sabado: `${agency.horario.sabado.apertura}–${agency.horario.sabado.cierre}`,
});

const agencyIsOpenNow = (agency, timestamp = Date.now()) => {
  const current = limaParts(new Date(timestamp));
  const weekday = new Date(`${current.year}-${current.month}-${current.day}T00:00:00Z`).getUTCDay();
  const schedule = weekday >= 1 && weekday <= 5
    ? agency.horario.lunesViernes
    : weekday === 6
      ? agency.horario.sabado
      : null;
  if (!schedule) return false;
  const currentMinute = Number(current.hour) * 60 + Number(current.minute);
  const opening = Number(schedule.apertura.slice(0, 2)) * 60 + Number(schedule.apertura.slice(3, 5));
  const closing = Number(schedule.cierre.slice(0, 2)) * 60 + Number(schedule.cierre.slice(3, 5));
  return currentMinute >= opening && currentMinute < closing;
};

const arrivedAppointments = (agencyId, attentionType) => [...tickets.values()]
  .filter((ticket) => ticket.agencia === agencyId
    && (!attentionType || ticket.tipoAtencion === attentionType)
    && ticket.estado === 'EN_SALA')
  .sort((a, b) => a.citaAt - b.citaAt || a.creado - b.creado);

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
  tipoAtencion: t.tipoAtencion,
  persona: t.persona ? {
    nombre: t.persona.nombre,
    dni: `****${t.persona.dni.slice(-4)}`,
  } : null,
  cita: { fecha: t.fechaCita, hora: t.horaCita },
  estado: t.estado,
  turnosPrevios: t.citaAt > Date.now()
    ? 0
    : arrivedAppointments(t.agencia, t.tipoAtencion)
      .filter((ticket) => ticket.citaAt < t.citaAt && ticket.citaAt <= Date.now()).length,
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
    const colas = Object.fromEntries(ATTENTION_TYPES.map((attentionType) => {
      const enCola = arrivedAppointments(a.id, attentionType)
        .filter((ticket) => ticket.citaAt <= Date.now()).length;
      return [attentionType, { enCola, tiempoEstimadoMin: enCola * 4 }];
    }));
    const enCola = Object.values(colas).reduce((total, fila) => total + fila.enCola, 0);
    return {
      id: a.id,
      nombre: a.nombre,
      direccion: a.direccion,
      enCola,
      tiempoEstimadoMin: enCola * 4,
      colas,
      horario: getAgencyHours(a),
      distanciaKm: Number.isFinite(lat) && Number.isFinite(lng) ? +km(lat, lng, a.lat, a.lng).toFixed(1) : null,
    };
  });
  list.sort((x, y) => (x.distanciaKm ?? Number.MAX_SAFE_INTEGER) - (y.distanciaKm ?? Number.MAX_SAFE_INTEGER));
  res.json(list);
});

app.get('/api/v1/appointments/slots', requireApiRole('user'), (req, res) => {
  const agencyId = readAgencyId(req.query.agencyId);
  const agency = agencyId ? agencies[agencyId] : null;
  const attentionType = readAttentionType(req.query.tipoAtencion);
  if (!agency) return res.status(400).json({ error: 'Agencia no válida o inexistente' });
  if (!attentionType) return res.status(400).json({ error: 'Selecciona Plataforma o Ventanilla' });
  if (!dateWithinBookingWindow(req.query.date)) {
    return res.status(400).json({ error: 'Selecciona una fecha entre hoy y los próximos 14 días' });
  }

  res.json({
    agencia: agency.id,
    fecha: req.query.date,
    horario: getAgencyHours(agency),
    zonaHoraria: 'America/Lima',
    tipoAtencion: attentionType,
    slots: getSlotsForDate(agency, req.query.date, attentionType),
  });
});

app.get('/api/v1/health', (_req, res) => {
  res.json({ ok: true, uptime: process.uptime(), port: PORT });
});

app.get('/api/v1/agencies/:id/board', requireApiRole('admin'), (req, res) => {
  const agencyId = readAgencyId(req.params.id);
  const ag = agencyId ? agencies[agencyId] : null;
  const attentionType = readAttentionType(req.query.tipoAtencion);
  if (!ag) return res.status(404).json({ error: 'Agencia no encontrada' });
  if (!attentionType) return res.status(400).json({ error: 'Selecciona Plataforma o Ventanilla' });

  const agencyTickets = [...tickets.values()]
    .filter((ticket) => ticket.agencia === ag.id && ticket.tipoAtencion === attentionType)
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
    agencia: { id: ag.id, nombre: ag.nombre, direccion: ag.direccion, horario: getAgencyHours(ag) },
    tipoAtencion: attentionType,
    atendiendo: current ? {
      id: current.id,
      tramite: current.tramite,
      estado: current.estado,
      llamado: current.llamado,
      cita: { fecha: current.fechaCita, hora: current.horaCita },
      persona: current.persona.nombre,
    } : null,
    enCola: arrivedAppointments(ag.id, attentionType).filter((ticket) => ticket.citaAt <= Date.now()).length,
    totalAtendidos: agencyTickets.filter((ticket) => ticket.estado === 'ATENDIDO').length,
    historial: history,
  });
});

// ---- 2. Generación: ticket + hash dinámico + QR
app.post('/api/v1/tickets', requireApiRole('user'), async (req, res) => {
  const { agencyId, tramite, nombre, dni, fechaCita, horaCita } = req.body || {};
  const normalizedAgencyId = readAgencyId(agencyId);
  const attentionType = readAttentionType(req.body?.tipoAtencion);
  const normalizedName = typeof nombre === 'string' ? nombre.trim().replace(/\s+/g, ' ') : '';
  const normalizedDni = typeof dni === 'string' ? dni.trim() : '';

  if (!normalizedAgencyId || !agencies[normalizedAgencyId]) {
    return res.status(400).json({ error: 'Agencia no válida o inexistente' });
  }
  if (!attentionType) return res.status(400).json({ error: 'Selecciona Plataforma o Ventanilla' });
  if (normalizedName.length < 2 || normalizedName.length > 100 || /[\u0000-\u001f\u007f]/.test(normalizedName)) {
    return res.status(400).json({ error: 'Ingresa el nombre de la persona (de 2 a 100 caracteres)' });
  }
  if (!/^\d{8}$/.test(normalizedDni)) {
    return res.status(400).json({ error: 'Ingresa un DNI válido de 8 dígitos' });
  }
  if (!dateWithinBookingWindow(fechaCita) || typeof horaCita !== 'string') {
    return res.status(400).json({ error: 'Selecciona una fecha y hora de cita disponibles' });
  }
  const availableSlots = getSlotsForDate(agencies[normalizedAgencyId], fechaCita, attentionType);
  const selectedSlot = availableSlots?.find((slot) => slot.hora === horaCita);
  if (!selectedSlot?.disponible) {
    return res.status(409).json({ error: 'Ese horario ya no está disponible. Actualiza los horarios e intenta de nuevo.' });
  }
  const duplicateActiveTicket = [...tickets.values()].some((ticket) =>
    ticket.agencia === normalizedAgencyId
    && ticket.persona?.dni === normalizedDni
    && ticket.estado !== 'ATENDIDO'
    && (ticket.estado !== 'ESPERANDO' || ticket.citaAt + 30 * 60 * 1000 > Date.now()));
  if (duplicateActiveTicket) {
    return res.status(409).json({ error: 'Este DNI ya tiene un turno activo en esta agencia' });
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
      tipoAtencion: attentionType,
      persona: { nombre: normalizedName, dni: normalizedDni },
      fechaCita,
      horaCita,
      citaAt: appointmentTimestamp(fechaCita, horaCita),
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
  const expectedAttentionType = req.body?.tipoAtencion == null
    ? null
    : readAttentionType(req.body.tipoAtencion);
  if (req.body?.agencyId != null && (!expectedAgencyId || !agencies[expectedAgencyId])) {
    return res.status(400).json({ error: 'Agencia administradora no válida' });
  }
  if (req.body?.tipoAtencion != null && !expectedAttentionType) {
    return res.status(400).json({ error: 'Tipo de atención no válido' });
  }
  if (expectedAgencyId && expectedAgencyId !== agencia) {
    return res.status(409).json({ error: 'Este ticket pertenece a otra agencia' });
  }

  const t = tickets.get(ticketKey(agencia, id));
  if (!t || sign(id, agencia) !== hash) return res.status(401).json({ error: 'Ticket no válido' });
  if (expectedAttentionType && expectedAttentionType !== t.tipoAtencion) {
    return res.status(409).json({ error: 'Este turno pertenece a otro tipo de atención' });
  }
  if (t.estado === 'EN_SALA') return res.json({ ...view(t), yaValidado: true });
  if (t.estado === 'ATENDIENDO') return res.json({ ...view(t), yaLlamado: true });
  if (t.estado === 'ATENDIDO') return res.status(409).json({ error: 'Este turno ya fue atendido' });
  if (t.estado !== 'ESPERANDO') return res.status(409).json({ error: `No se puede validar un ticket en estado ${t.estado}` });
  if (!agencyIsOpenNow(agencies[agencia])) {
    return res.status(409).json({ error: 'La agencia está cerrada. Registra tu llegada durante su horario de atención.' });
  }
  const now = Date.now();
  const todayInLima = limaParts(new Date(now));
  const today = `${todayInLima.year}-${todayInLima.month}-${todayInLima.day}`;
  if (t.fechaCita !== today || now > t.citaAt + 30 * 60 * 1000) {
    return res.status(409).json({ error: 'La cita no corresponde al horario vigente o ya venció. Contacta a la agencia.' });
  }

  t.estado = 'EN_SALA';
  emit(ticketKey(agencia, id), 'estado', view(t));
  res.json(view(t));
});

// ---- Ventanilla: llamar al siguiente turno y disparar alertas push
app.post('/api/v1/agencies/:id/next', requireApiRole('admin'), (req, res) => {
  const agencyId = readAgencyId(req.params.id);
  const attentionType = readAttentionType(req.query.tipoAtencion);
  if (!agencyId || !agencies[agencyId]) return res.status(400).json({ error: 'Agencia no válida' });
  if (!attentionType) return res.status(400).json({ error: 'Selecciona Plataforma o Ventanilla' });

  const ag = agencies[agencyId];
  if (!agencyIsOpenNow(ag)) {
    return res.status(409).json({ error: 'La agencia está fuera de su horario de atención' });
  }
  const previousTicket = [...tickets.values()].find((ticket) =>
    ticket.agencia === ag.id
    && ticket.tipoAtencion === attentionType
    && ticket.estado === 'ATENDIENDO');
  if (previousTicket?.estado === 'ATENDIENDO') {
    previousTicket.estado = 'ATENDIDO';
    emit(ticketKey(ag.id, previousTicket.id), 'estado', view(previousTicket));
  }

  const now = Date.now();
  const nextTicket = arrivedAppointments(ag.id, attentionType).find((ticket) => ticket.citaAt <= now);
  if (!nextTicket) {
    return res.status(409).json({ error: 'No hay citas pendientes listas para llamar. Registra la llegada y espera la hora reservada.' });
  }

  nextTicket.estado = 'ATENDIENDO';
  nextTicket.llamado = now;
  emit(ticketKey(ag.id, nextTicket.id), 'estado', view(nextTicket));

  for (const ticket of arrivedAppointments(ag.id, attentionType)) {
    emit(ticketKey(ag.id, ticket.id), 'estado', view(ticket));
    const previos = arrivedAppointments(ag.id, attentionType)
      .filter((waiting) => waiting.citaAt < ticket.citaAt).length;
    if (previos <= PUSH_THRESHOLD && !ticket.notificado) {
      ticket.notificado = true;
      emit(ticketKey(ag.id, ticket.id), 'push', {
        titulo: 'BCP Ticket Express',
        mensaje: `Tu cita se acerca. Acércate a ${attentionType}`,
        restan: previos,
      });
    }
  }

  res.json({
    agencia: ag.id,
    tipoAtencion: attentionType,
    turno: nextTicket.id,
    atendiendo: nextTicket.numero,
    enCola: arrivedAppointments(ag.id, attentionType).filter((ticket) => ticket.citaAt <= Date.now()).length,
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
