// Намерно ранлива лабораторија. Не користете ја како продукциски JWT код.
const http = require('node:http');
const crypto = require('node:crypto');

const weakSecret = Buffer.from('secret123');
const strongSecret = crypto.randomBytes(32);
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });

const b64 = (value) => Buffer.from(value).toString('base64url');
const json64 = (value) => b64(JSON.stringify(value));

function signHs(payload, secret) {
  const input = `${json64({ alg: 'HS256', typ: 'JWT' })}.${json64(payload)}`;
  const signature = crypto.createHmac('sha256', secret).update(input).digest();
  return `${input}.${b64(signature)}`;
}

function signRs(payload) {
  const input = `${json64({ alg: 'RS256', typ: 'JWT' })}.${json64(payload)}`;
  const signature = crypto.sign('RSA-SHA256', Buffer.from(input), privateKey);
  return `${input}.${b64(signature)}`;
}

function parse(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw Error('Неправилен формат на токен');
  const [h, p, s] = parts;
  const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8'));
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
  if (!header || !payload || typeof header !== 'object' || typeof payload !== 'object') {
    throw Error('Неправилен JSON');
  }
  return { header, payload, input: `${h}.${p}`, signature: s };
}

function equalMac(actual, expected) {
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function verifyHs(token, secret) {
  const data = parse(token);
  if (data.header.alg !== 'HS256' || !data.signature) throw Error('Недозволен алгоритам');
  const expected = crypto.createHmac('sha256', secret).update(data.input).digest();
  if (!equalMac(Buffer.from(data.signature, 'base64url'), expected)) throw Error('Невалиден потпис');
  return data.payload;
}

// ГРЕШКА 1: токенот избира дали воопшто ќе има проверка на потпис.
function verifyVulnerableNone(token) {
  const data = parse(token);
  if (data.header.alg === 'none' && data.signature === '') return data.payload;
  return verifyHs(token, weakSecret);
}

function verifyRs(token) {
  const data = parse(token);
  if (data.header.alg !== 'RS256' || !data.signature) throw Error('Недозволен алгоритам');
  const valid = crypto.verify(
    'RSA-SHA256', Buffer.from(data.input), publicKey,
    Buffer.from(data.signature, 'base64url')
  );
  if (!valid) throw Error('Невалиден потпис');
  return data.payload;
}

// ГРЕШКА 3: јавниот RSA клуч се третира како HMAC тајна ако header-от бара HS256.
function verifyVulnerableConfusion(token) {
  const data = parse(token);
  if (data.header.alg === 'RS256') return verifyRs(token);
  if (data.header.alg === 'HS256') return verifyHs(token, Buffer.from(publicKeyPem));
  throw Error('Недозволен алгоритам');
}

function reply(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

function bearer(req) {
  const value = req.headers.authorization || '';
  if (!value.startsWith('Bearer ')) throw Error('Недостасува Bearer токен');
  return value.slice(7);
}

function handleAdmin(req, res, verify) {
  try {
    const payload = verify(bearer(req));
    if (payload.role !== 'admin') return reply(res, 403, { error: 'Потребна е admin улога' });
    return reply(res, 200, { message: `Добредојде, ${payload.username}`, role: payload.role });
  } catch (error) {
    return reply(res, 401, { error: error.message });
  }
}

const server = http.createServer(async (req, res) => {
  const path = new URL(req.url, 'http://localhost').pathname;
  if (req.method === 'GET' && path === '/') {
    return reply(res, 200, { lab: 'JWT vulnerabilities', routes: ['/login', '/admin', '/admin-alg-safe', '/admin-secret-safe', '/rsa-token', '/confusion-demo', '/confusion-demo-safe'] });
  }
  if (req.method === 'POST' && path === '/login') {
    try {
      let raw = '';
      for await (const chunk of req) {
        raw += chunk;
        if (raw.length > 4096) throw Error('Барањето е преголемо');
      }
      const body = JSON.parse(raw);
      if (body.username !== 'alice' || body.password !== 'demo-pass') {
        return reply(res, 401, { error: 'Погрешни тест-податоци' });
      }
      return reply(res, 200, { token: signHs({ username: 'alice', role: 'user' }, weakSecret) });
    } catch (error) {
      return reply(res, 400, { error: error.message });
    }
  }
  if (req.method === 'GET' && path === '/admin') return handleAdmin(req, res, verifyVulnerableNone);
  if (req.method === 'GET' && path === '/admin-alg-safe') return handleAdmin(req, res, (token) => verifyHs(token, weakSecret));
  if (req.method === 'GET' && path === '/admin-secret-safe') return handleAdmin(req, res, (token) => verifyHs(token, strongSecret));
  if (req.method === 'GET' && path === '/rsa-token') {
    return reply(res, 200, { token: signRs({ username: 'alice', role: 'user' }), publicKey: publicKeyPem });
  }
  if (req.method === 'GET' && path === '/confusion-demo') {
    return handleAdmin(req, res, verifyVulnerableConfusion);
  }
  if (req.method === 'GET' && path === '/confusion-demo-safe') {
    return handleAdmin(req, res, verifyRs);
  }
  return reply(res, 404, { error: 'Непозната рута' });
});

server.listen(3000, '0.0.0.0', () => console.log('JWT lab listening on port 3000'));
