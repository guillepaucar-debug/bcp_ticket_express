import 'dotenv/config';
import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

const email = process.argv[2]?.trim().toLowerCase();
const serviceAccountValue = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

if (!email || !serviceAccountValue) {
  console.error('Uso: npm run set-admin -- correo@dominio.com (requiere FIREBASE_SERVICE_ACCOUNT_JSON)');
  process.exit(1);
}

try {
  const serviceAccount = JSON.parse(serviceAccountValue);
  serviceAccount.private_key = serviceAccount.private_key?.replace(/\\n/g, '\n');
  const app = getApps()[0] || initializeApp({ credential: cert(serviceAccount) });
  const auth = getAuth(app);
  const user = await auth.getUserByEmail(email);
  await auth.setCustomUserClaims(user.uid, { ...user.customClaims, role: 'admin' });
  console.log(`Rol de administrador asignado a ${user.email}.`);
} catch (error) {
  console.error('No se pudo asignar el rol de administrador:', error.message);
  process.exitCode = 1;
}
