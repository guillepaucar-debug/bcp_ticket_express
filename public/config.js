window.BCP_CONFIG = {
  apiBaseUrl: ['localhost', '127.0.0.1'].includes(window.location.hostname)
    ? ''
    : 'https://YOUR-SERVICE-NAME.onrender.com',
};
