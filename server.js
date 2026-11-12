const express = require('express');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

if (!process.env.PASSWORD_HASH || !process.env.SESSION_KEYS) {
  console.error('Set PASSWORD_HASH and SESSION_KEYS environment variables before starting.');
  process.exit(1);
}

if (isProduction) app.set('trust proxy', 1);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

app.use(cookieSession({
  name: 'expiry_private_session',
  keys: process.env.SESSION_KEYS.split(','),
  maxAge: 8 * 60 * 60 * 1000,
  httpOnly: true,
  secure: isProduction,
  sameSite: 'strict',
  path: '/'
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: 'Слишком много попыток входа. Попробуйте через 15 минут.'
});

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated === true) return next();
  return res.redirect('/login');
}

function loginPage(error = '') {
  return `<!doctype html>
  <html lang="ru"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>Вход — Сроки годности</title>
  <style>
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1220;color:#e5edf8;font:16px system-ui,sans-serif;padding:20px}
  main{width:min(100%,390px);background:#131d2e;border:1px solid #29384e;border-radius:18px;padding:28px}
  h1{font-size:23px;margin:0 0 8px}p{color:#9aabc2;font-size:14px;line-height:1.5}
  label{display:block;margin:20px 0 7px;font-size:14px}input{width:100%;padding:13px;border-radius:10px;border:1px solid #40516b;background:#182438;color:#fff;font:inherit}
  button{width:100%;margin-top:16px;padding:13px;border:0;border-radius:10px;background:#60a5fa;color:#081426;font-weight:700;font:inherit;cursor:pointer}
  .error{color:#fca5a5;background:#351e28;padding:10px;border-radius:9px}
  </style></head><body><main><h1>🔒 Сроки годности</h1>
  <p>Это личное приложение. Введите пароль, чтобы продолжить.</p>
  ${error ? `<p class="error">${error}</p>` : ''}
  <form method="post" action="/login">
  <label for="password">Пароль</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
  <button type="submit">Войти</button></form></main></body></html>`;
}

app.get('/', (req, res) => res.redirect(req.session?.authenticated ? '/app' : '/login'));
app.get('/login', (req, res) => {
  if (req.session?.authenticated) return res.redirect('/app');
  res.set('Cache-Control', 'no-store');
  res.type('html').send(loginPage());
});

app.post('/login', loginLimiter, async (req, res) => {
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const ok = await bcrypt.compare(password, process.env.PASSWORD_HASH);
  if (!ok) {
    res.status(401).set('Cache-Control', 'no-store').type('html').send(loginPage('Неверный пароль.'));
    return;
  }
  req.session = { authenticated: true, createdAt: Date.now() };
  res.redirect(303, '/app');
});

app.get('/app', requireAuth, (req, res) => {
  res.set({
    'Cache-Control': 'no-store, private',
    'X-Robots-Tag': 'noindex, nofollow'
  });
  res.sendFile(path.join(__dirname, 'private', 'app.html'));
});

app.post('/logout', requireAuth, (req, res) => {
  req.session = null;
  res.redirect(303, '/login');
});

app.use((req, res) => res.status(404).send('Страница не найдена.'));

app.listen(PORT, () => console.log(`Private expiry tracker listening on port ${PORT}`));
