// Si la página se abre desde el propio servidor (localhost o Render), la API está en el mismo origen.
// Solo si el frontend está en otro sitio (por ejemplo Firebase Hosting) se usa la URL de Render.
const sameOriginHosts = ['localhost', '127.0.0.1'];
const isSameOrigin = sameOriginHosts.includes(window.location.hostname)
  || window.location.hostname.endsWith('.onrender.com');

window.BCP_CONFIG = {
  apiBaseUrl: isSameOrigin ? '' : 'https://bcp-ticket-express.onrender.com',
};
