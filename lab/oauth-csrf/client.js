const http = require('http');
const crypto = require('crypto');

const PORT = 8000;
const AUTH_PUBLIC_URL = process.env.AUTH_PUBLIC_URL || 'http://localhost:9000';
const AUTH_INTERNAL_URL = process.env.AUTH_INTERNAL_URL || AUTH_PUBLIC_URL;
const CLIENT_ID = 'oauth-lab-client';
const VULNERABLE_REDIRECT = 'http://localhost:8000/callback';
const SECURE_REDIRECT = 'http://localhost:8000/secure-callback';

const sessions = new Map();
const notes = new Map();

function randomValue() {
  return crypto.randomBytes(24).toString('base64url');
}

function escapeHtml(value = '') {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function layout(title, content) {
  return `<!doctype html>
<html lang="mk">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <style>
    body{font:16px/1.55 system-ui,sans-serif;max-width:800px;margin:48px auto;padding:0 20px;color:#172033;background:#f4f7fb}
    main{background:white;padding:28px;border-radius:14px;box-shadow:0 8px 30px #1f2d3d18}
    nav{display:flex;gap:12px;justify-content:space-between;align-items:center}h1{margin-top:12px}
    code{background:#eef2f7;padding:2px 5px;border-radius:4px}.button,button{display:inline-block;border:0;border-radius:8px;padding:11px 16px;margin:6px 8px 6px 0;background:#b42318;color:white;text-decoration:none;font-weight:650}
    .secure{background:#18794e}.secondary{background:#596579}.identity{padding:14px;background:#edf5ff;border-left:4px solid #3478db}.warning{padding:12px 14px;background:#fff4d8;border-left:4px solid #e3a008}
    input{box-sizing:border-box;width:100%;padding:10px;border:1px solid #aeb8c6;border-radius:7px;margin:6px 0}li{margin:8px 0}
  </style>
</head>
<body><main>${content}</main></body>
</html>`;
}

function sendHtml(res, status, title, content, extraHeaders = {}) {
  const body = layout(title, content);
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(body), ...extraHeaders });
  res.end(body);
}

function redirect(res, location, extraHeaders = {}) {
  res.writeHead(302, { location, 'cache-control': 'no-store', ...extraHeaders });
  res.end();
}

function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(part => {
    const index = part.indexOf('=');
    return [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1))];
  }));
}

function readForm(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 20_000) req.destroy();
    });
    req.on('end', () => resolve(new URLSearchParams(body)));
    req.on('error', reject);
  });
}

async function exchangeCode(code, redirectUri) {
  const response = await fetch(`${AUTH_INTERNAL_URL}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      redirect_uri: redirectUri,
    }),
  });
  if (!response.ok) throw new Error('Authorization code не е валиден или веќе е искористен.');
  const tokenResponse = await response.json();
  const userResponse = await fetch(`${AUTH_INTERNAL_URL}/userinfo`, {
    headers: { authorization: `Bearer ${tokenResponse.access_token}` },
  });
  if (!userResponse.ok) throw new Error('Access token е одбиен.');
  return userResponse.json();
}

function authorizationUrl(redirectUri, capture, state = '') {
  const target = new URL('/authorize', AUTH_PUBLIC_URL);
  target.searchParams.set('response_type', 'code');
  target.searchParams.set('client_id', CLIENT_ID);
  target.searchParams.set('redirect_uri', redirectUri);
  target.searchParams.set('scope', 'profile');
  if (state) target.searchParams.set('state', state);
  if (capture) target.searchParams.set('lab_capture', '1');
  return target.toString();
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const jar = cookies(req);
    const session = sessions.get(jar.client_session);

    if (req.method === 'GET' && url.pathname === '/') {
      const identity = session
        ? `<div class="identity"><strong>Активна апликациска сесија:</strong><br>Име: ${escapeHtml(session.name)}<br>OAuth subject: <code>${escapeHtml(session.sub)}</code></div>`
        : '<p class="warning">Во моментот нема активна сесија.</p>';
      const userNotes = session ? (notes.get(session.sub) || []) : [];
      const notesHtml = session
        ? `<h2>Приватни белешки</h2>
           <ul>${userNotes.map(note => `<li>${escapeHtml(note)}</li>`).join('') || '<li>Нема белешки.</li>'}</ul>
           <form method="post" action="/notes"><label for="note">Нова белешка</label><input id="note" name="note" required placeholder="Внеси доверлива белешка"><button type="submit">Зачувај</button></form>`
        : '';
      return sendHtml(res, 200, 'OAuth Notes Lab', `
        <nav><strong>OAuth Notes Lab</strong><a href="/logout">Одјави се</a></nav>
        <h1>Клиентска апликација</h1>
        ${identity}
        <p><a class="button" href="/login">Ранлива OAuth најава</a><a class="button secure" href="/secure-login">Заштитена најава со state</a></p>
        ${notesHtml}
        <p><a class="button secondary" href="http://127.0.0.1:7000">Отвори ја страницата на напаѓачот</a></p>`);
    }

    if (req.method === 'GET' && url.pathname === '/login') {
      // Намерно ранливо: не се создава и не се испраќа state.
      return redirect(res, authorizationUrl(VULNERABLE_REDIRECT, url.searchParams.get('capture') === '1'));
    }

    if (req.method === 'GET' && url.pathname === '/callback') {
      const code = url.searchParams.get('code');
      if (!code) return sendHtml(res, 400, 'Недостасува code', '<h1>Недостасува authorization code</h1>');

      // РАНЛИВОСТ: callback-от прифаќа code без state и без проверка дека
      // овој прелистувач ја започнал OAuth трансакцијата.
      const user = await exchangeCode(code, VULNERABLE_REDIRECT);
      const sessionId = randomValue();
      sessions.set(sessionId, user);
      return redirect(res, '/', { 'set-cookie': `client_session=${sessionId}; HttpOnly; SameSite=Lax; Path=/` });
    }

    if (req.method === 'GET' && url.pathname === '/secure-login') {
      const state = randomValue();
      const capture = url.searchParams.get('capture') === '1';
      return redirect(res, authorizationUrl(SECURE_REDIRECT, capture, state), {
        'set-cookie': `oauth_state=${state}; HttpOnly; SameSite=Lax; Max-Age=300; Path=/`,
      });
    }

    if (req.method === 'GET' && url.pathname === '/secure-callback') {
      const code = url.searchParams.get('code');
      const returnedState = url.searchParams.get('state');
      if (!code || !returnedState || !jar.oauth_state || returnedState !== jar.oauth_state) {
        return sendHtml(res, 403, 'OAuth напад блокиран', `
          <h1>OAuth одговорот е одбиен</h1>
          <p class="warning">Вредноста <code>state</code> недостасува или не припаѓа на OAuth трансакција започната во овој прелистувач.</p>
          <p>Ова е очекуваниот резултат на заштитената варијанта.</p>
          <a class="button secure" href="/">Назад</a>`);
      }
      const user = await exchangeCode(code, SECURE_REDIRECT);
      const sessionId = randomValue();
      sessions.set(sessionId, user);
      return redirect(res, '/', {
        'set-cookie': [
          `client_session=${sessionId}; HttpOnly; SameSite=Lax; Path=/`,
          'oauth_state=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/',
        ],
      });
    }

    if (req.method === 'POST' && url.pathname === '/notes') {
      if (!session) return redirect(res, '/');
      const form = await readForm(req);
      const note = (form.get('note') || '').trim().slice(0, 300);
      if (note) notes.set(session.sub, [...(notes.get(session.sub) || []), note]);
      return redirect(res, '/');
    }

    if (req.method === 'GET' && url.pathname === '/logout') {
      if (jar.client_session) sessions.delete(jar.client_session);
      return redirect(res, '/', { 'set-cookie': 'client_session=; HttpOnly; SameSite=Lax; Max-Age=0; Path=/' });
    }

    sendHtml(res, 404, 'Not found', '<h1>404</h1>');
  } catch (error) {
    console.error(error);
    sendHtml(res, 400, 'Грешка', `<h1>Барањето не успеа</h1><p>${escapeHtml(error.message)}</p><a class="button secondary" href="/">Назад</a>`);
  }
});

server.listen(PORT, '0.0.0.0', () => console.log(`OAuth client listening on ${PORT}`));
