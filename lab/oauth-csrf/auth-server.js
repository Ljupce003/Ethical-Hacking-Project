const http = require('http');
const crypto = require('crypto');

const PORT = 9000;
const ATTACKER_PUBLIC_URL = process.env.ATTACKER_PUBLIC_URL || 'http://127.0.0.1:7000';
const CLIENT_ID = 'oauth-lab-client';
const ALLOWED_REDIRECTS = new Set([
  'http://localhost:8000/callback',
  'http://localhost:8000/secure-callback',
]);

const codes = new Map();
const tokens = new Map();
const users = {
  attacker: { sub: 'user-attacker', name: 'Алекс Напаѓач', username: 'attacker' },
  victim: { sub: 'user-victim', name: 'Виктор Жртва', username: 'victim' },
};

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
    body{font:16px/1.55 system-ui,sans-serif;max-width:760px;margin:48px auto;padding:0 20px;color:#172033;background:#f4f7fb}
    main{background:white;padding:28px;border-radius:14px;box-shadow:0 8px 30px #1f2d3d18}
    h1{margin-top:0} code{background:#eef2f7;padding:2px 5px;border-radius:4px;overflow-wrap:anywhere}
    button,.button{display:inline-block;border:0;border-radius:8px;padding:11px 16px;margin:6px 8px 6px 0;background:#2457d6;color:white;text-decoration:none;font-weight:650}
    .secondary{background:#596579}.warning{padding:12px 14px;background:#fff4d8;border-left:4px solid #e3a008}
  </style>
</head>
<body><main>${content}</main></body>
</html>`;
}

function sendHtml(res, status, title, content) {
  const body = layout(title, content);
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

function redirect(res, location) {
  res.writeHead(302, { location, 'cache-control': 'no-store' });
  res.end();
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

function appendState(callbackUrl, state) {
  const target = new URL(callbackUrl);
  if (state) target.searchParams.set('state', state);
  return target.toString();
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'GET' && url.pathname === '/') {
    return sendHtml(res, 200, 'LabID OAuth Server', `
      <h1>LabID OAuth Server</h1>
      <p>Ова е локален, намерно поедноставен OAuth 2.0 Authorization Server за лабораториската вежба.</p>
      <p>Регистриран клиент: <code>${CLIENT_ID}</code></p>`);
  }

  if (req.method === 'GET' && url.pathname === '/authorize') {
    const clientId = url.searchParams.get('client_id');
    const redirectUri = url.searchParams.get('redirect_uri');
    const responseType = url.searchParams.get('response_type');
    const state = url.searchParams.get('state') || '';
    const capture = url.searchParams.get('lab_capture') === '1';

    if (clientId !== CLIENT_ID || responseType !== 'code' || !ALLOWED_REDIRECTS.has(redirectUri)) {
      return sendHtml(res, 400, 'Невалидно барање', '<h1>Невалидно OAuth барање</h1><p>client_id, response_type или redirect_uri не е дозволен.</p>');
    }

    const hidden = `
      <input type="hidden" name="client_id" value="${escapeHtml(clientId)}">
      <input type="hidden" name="redirect_uri" value="${escapeHtml(redirectUri)}">
      <input type="hidden" name="state" value="${escapeHtml(state)}">
      <input type="hidden" name="lab_capture" value="${capture ? '1' : '0'}">`;

    return sendHtml(res, 200, 'OAuth согласност', `
      <h1>Најава во LabID</h1>
      <p>Апликацијата <code>${CLIENT_ID}</code> бара пристап до основниот профил.</p>
      <p>Избери ја сметката што ја симулираш:</p>
      <form method="post" action="/approve">${hidden}<button name="user" value="attacker">Најави се како напаѓач</button></form>
      <form method="post" action="/approve">${hidden}<button class="secondary" name="user" value="victim">Најави се како жртва</button></form>
      ${capture ? '<p class="warning">Lab capture е активен. По одобрувањето, серверот ќе ја прикаже callback-врската наместо автоматски да пренасочи.</p>' : ''}`);
  }

  if (req.method === 'POST' && url.pathname === '/approve') {
    const form = await readForm(req);
    const user = users[form.get('user')];
    const clientId = form.get('client_id');
    const redirectUri = form.get('redirect_uri');
    const state = form.get('state') || '';
    const capture = form.get('lab_capture') === '1';

    if (!user || clientId !== CLIENT_ID || !ALLOWED_REDIRECTS.has(redirectUri)) {
      return sendHtml(res, 400, 'Невалидно одобрување', '<h1>Барањето е одбиено</h1>');
    }

    const code = randomValue();
    codes.set(code, { clientId, redirectUri, user, used: false, expiresAt: Date.now() + 120_000 });
    const callback = new URL(redirectUri);
    callback.searchParams.set('code', code);
    const callbackWithState = appendState(callback.toString(), state);

    if (!capture) return redirect(res, callbackWithState);

    const builder = `${ATTACKER_PUBLIC_URL}/?target=${encodeURIComponent(callbackWithState)}`;
    return sendHtml(res, 200, 'Lab capture', `
      <h1>Authorization response е пресретнат</h1>
      <p>Во реална анализа оваа <code>Location</code> вредност би се пресретнала со proxy како Burp Suite. Lab helper ја прикажува директно:</p>
      <p><code>${escapeHtml(callbackWithState)}</code></p>
      <p><a class="button" href="${escapeHtml(builder)}">Пренеси ја во страницата на напаѓачот</a></p>
      <p class="warning">Не ја отворај callback-врската директно како напаѓач, бидејќи authorization code е еднократен.</p>`);
  }

  if (req.method === 'POST' && url.pathname === '/token') {
    const form = await readForm(req);
    const code = form.get('code');
    const record = codes.get(code);
    const valid = record && !record.used && record.expiresAt > Date.now()
      && form.get('grant_type') === 'authorization_code'
      && form.get('client_id') === record.clientId
      && form.get('redirect_uri') === record.redirectUri;

    if (!valid) {
      res.writeHead(400, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      return res.end(JSON.stringify({ error: 'invalid_grant' }));
    }

    record.used = true;
    const accessToken = randomValue();
    tokens.set(accessToken, record.user);
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    return res.end(JSON.stringify({ access_token: accessToken, token_type: 'Bearer', expires_in: 300, scope: 'profile' }));
  }

  if (req.method === 'GET' && url.pathname === '/userinfo') {
    const authorization = req.headers.authorization || '';
    const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
    const user = tokens.get(token);
    if (!user) {
      res.writeHead(401, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ error: 'invalid_token' }));
    }
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    return res.end(JSON.stringify(user));
  }

  sendHtml(res, 404, 'Not found', '<h1>404</h1>');
});

server.listen(PORT, '0.0.0.0', () => console.log(`LabID Authorization Server listening on ${PORT}`));
