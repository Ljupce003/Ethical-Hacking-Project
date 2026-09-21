import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { marked, Renderer } from 'marked';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const sourcePath = join(root, process.argv[2] || 'oauth2-elaborat.md');
const outputPath = join(root, process.argv[3] || 'oauth2-elaborat.html');
const source = await readFile(sourcePath, 'utf8');

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const diagrams = [
  `<figure class="diagram" aria-label="Улоги и движење на барањата во OAuth 2.0">
    <figcaption>Слика 1. Учесници и насока на комуникација</figcaption>
    <div class="roles">
      <div><strong>Корисник</strong><small>Resource Owner</small></div>
      <span aria-hidden="true">→</span>
      <div><strong>Прелистувач</strong><small>User Agent</small></div>
      <span aria-hidden="true">→</span>
      <div><strong>Апликација</strong><small>OAuth Client</small></div>
      <span aria-hidden="true">↔</span>
      <div><strong>OAuth провајдер</strong><small>Authorization Server</small></div>
    </div>
    <p class="diagram-note"><strong>Одделна врска:</strong> апликацијата го испраќа access token до заштитеното API (Resource Server) за да ги добие дозволените податоци.</p>
  </figure>`,
  `<figure class="diagram" aria-label="Референтен Authorization Code тек со PKCE">
    <figcaption>Слика 2. Референтен тек: Authorization Code + PKCE</figcaption>
    <div class="lane"><b>Front channel · преку прелистувач</b><ol>
      <li>Клиентот создава <code>state</code>, <code>code_verifier</code> и <code>code_challenge</code>.</li>
      <li>Прелистувачот оди на <code>/authorize</code> со <code>state</code> и <code>code_challenge</code>.</li>
      <li>Провајдерот го најавува корисникот и враќа <code>code</code> + <code>state</code>.</li>
    </ol></div>
    <div class="lane lane-back"><b>Back channel · сервер кон сервер</b><ol start="4">
      <li>Клиентот го проверува <code>state</code> и испраќа <code>code</code> + <code>code_verifier</code> до <code>/token</code>.</li>
      <li>Провајдерот го проверува PKCE и издава access token.</li>
      <li>Клиентот го користи токенот за пристап до API.</li>
    </ol></div>
  </figure>`,
  `<figure class="diagram" aria-label="Секвенца на лабораторискиот OAuth Login CSRF напад">
    <figcaption>Слика 3. Редослед на дејствата при Login CSRF</figcaption>
    <ol class="attack-flow">
      <li><b>Напаѓач</b> започнува OAuth најава без <code>state</code> и добива code за својата сметка.</li>
      <li><b>Attacker Site</b> подготвува врска што води до callback со тој code.</li>
      <li><b>Жртва</b> ја отвора врската во одвоен прелистувачки профил.</li>
      <li><b>Клиент</b> го прифаќа code и создава сесија како напаѓач.</li>
      <li><b>Жртва</b> внесува белешка; <b>напаѓачот</b> ја чита во својата сметка.</li>
    </ol>
  </figure>`,
];

const headings = [];
let headingIndex = 0;
let diagramIndex = 0;
const renderer = new Renderer();
renderer.heading = function ({ tokens, depth }) {
  const text = this.parser.parseInline(tokens);
  const id = `section-${++headingIndex}`;
  headings.push({ id, depth, label: text.replace(/<[^>]*>/g, '') });
  return `<h${depth} id="${id}">${text}</h${depth}>\n`;
};
renderer.code = function ({ text, lang }) {
  if (lang === 'mermaid') {
    const diagram = diagrams[diagramIndex++];
    if (!diagram) throw new Error('Missing static diagram replacement.');
    return `${diagram}\n`;
  }
  const language = lang ? `<span class="code-language">${escapeHtml(lang)}</span>` : '';
  return `<div class="code-block">${language}<pre><code>${escapeHtml(text)}</code></pre></div>`;
};

const body = marked.parse(source, { renderer, gfm: true, breaks: false });
if (diagramIndex !== diagrams.length) {
  throw new Error(`Expected ${diagrams.length} diagrams, found ${diagramIndex}.`);
}

const toc = headings
  .filter(({ depth }) => depth === 2 || depth === 3)
  .map(({ id, depth, label }) => `<li class="toc-${depth}"><a href="#${id}">${escapeHtml(label)}</a></li>`)
  .join('\n');

const tocHtml = `<nav class="toc" aria-label="Содржина"><h2>Содржина</h2><ol>${toc}</ol></nav>`;
const titleEnd = body.indexOf('</h1>');
const coverEnd = body.indexOf('</p>', titleEnd);
if (titleEnd < 0 || coverEnd < 0) throw new Error('Could not locate the report title and metadata.');
const reportBody = `<header class="cover">${body.slice(0, coverEnd + 4)}</header>\n${tocHtml}\n${body.slice(coverEnd + 4)}`;

const html = `<!doctype html>
<html lang="mk">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="description" content="Елаборат со локални лабораториски вежби за OAuth 2.0 и JWT ранливости.">
  <title>OAuth 2.0 и JWT ранливости — елаборат</title>
  <style>
    :root{color-scheme:light;--ink:#202020;--muted:#555;--rule:#9b9b9b;--paper:#fff}
    *{box-sizing:border-box}
    html{scroll-behavior:smooth}
    body{margin:0;background:#e7e7e7;color:var(--ink);font:17px/1.58 Georgia,"Times New Roman",serif}
    .page{max-width:860px;margin:0 auto;padding:58px clamp(24px,6vw,78px);background:var(--paper);min-height:100vh}
    .cover{min-height:355px;display:flex;flex-direction:column;justify-content:center;text-align:center;border-bottom:1px solid var(--rule);margin-bottom:42px;padding:20px 0 54px}
    .cover h1{font:700 clamp(1.8rem,3.8vw,2.6rem)/1.23 Georgia,"Times New Roman",serif;margin:0 auto 38px;max-width:680px}
    .cover p{font:15px/1.8 Arial,Helvetica,sans-serif;color:var(--ink);margin:0;text-align:center}
    h1,h2,h3,h4{scroll-margin-top:20px;line-height:1.27;color:#171717}
    h2{font-size:1.52rem;margin:2.8rem 0 1rem;padding-bottom:.35rem;border-bottom:1px solid var(--rule)}
    h3{font-size:1.18rem;margin:2rem 0 .65rem}
    h4{font-size:1rem;margin:1.5rem 0 .45rem}
    p{margin:.65rem 0 .95rem;text-align:justify;hyphens:auto}
    ul,ol{padding-left:1.5rem;margin:.6rem 0 1rem}
    li{padding-left:.1rem;margin:.32rem 0}
    li>p{margin:.16rem 0;text-align:left}
    strong{font-weight:700}
    a{color:#222;text-decoration:underline;text-underline-offset:2px}
    a:hover{color:#555}
    code{font:.86em/1.35 ui-monospace,SFMono-Regular,Consolas,monospace;background:#f1f1f1;padding:.1em .25em;overflow-wrap:anywhere}
    .code-block{margin:1rem 0 1.2rem;border:1px solid #b6b6b6;background:#f8f8f8;break-inside:avoid}
    .code-language{display:block;border-bottom:1px solid #d1d1d1;padding:.25rem .7rem;color:var(--muted);font:11px/1.2 Arial,Helvetica,sans-serif;text-transform:uppercase;letter-spacing:.06em}
    .code-block pre{margin:0;padding:.75rem .9rem;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}
    .code-block code{font-size:.8rem;background:none;padding:0}
    table{border-collapse:collapse;width:100%;margin:1.1rem 0 1.4rem;border-top:1px solid #555;border-bottom:1px solid #555;font:14px/1.42 Arial,Helvetica,sans-serif}
    th,td{padding:.52rem .55rem;border-bottom:1px solid #c5c5c5;text-align:left;vertical-align:top}
    th{font-weight:700;background:#fafafa}
    tr:last-child td{border-bottom:0}
    td code{white-space:nowrap}
    blockquote{border-left:2px solid #777;margin:1.2rem 0;padding:.2rem .9rem;color:#333}
    blockquote p{margin:.25rem 0}
    .toc{padding:0 0 1.35rem;margin:0 0 2.6rem;border-bottom:1px solid var(--rule)}
    .toc h2{font-size:1.4rem;border:0;margin:0 0 1rem;padding:0;text-align:center}
    .toc ol{list-style:none;padding:0;margin:0;font:14px/1.45 Arial,Helvetica,sans-serif}
    .toc li{margin:.14rem 0;padding:.1rem 0}
    .toc .toc-2{font-weight:700;margin-top:.45rem}
    .toc .toc-3{padding-left:1.25rem}
    .toc a{text-decoration:none}
    .toc a:hover{text-decoration:underline}
    .diagram{display:flex;flex-direction:column;margin:1.5rem 0 1.8rem;padding:.9rem 0 .7rem;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule);break-inside:avoid}
    .diagram figcaption{order:2;margin:.8rem 0 0;text-align:center;font:13px/1.4 Arial,Helvetica,sans-serif;color:var(--muted)}
    .roles{display:flex;align-items:stretch;gap:.35rem}
    .roles div{flex:1;min-width:0;border:1px solid #888;padding:.45rem .25rem;text-align:center;display:flex;flex-direction:column;justify-content:center}
    .roles div strong{font:700 12px/1.25 Arial,Helvetica,sans-serif}
    .roles div small{font:10px/1.25 Arial,Helvetica,sans-serif;color:var(--muted)}
    .roles>span{align-self:center;font:700 14px Arial,Helvetica,sans-serif}
    .diagram-note{font:12px/1.4 Arial,Helvetica,sans-serif;color:var(--muted);margin:.55rem 0 0;text-align:left}
    .lane{padding:.25rem .8rem;margin:.4rem 0;border-left:2px solid #888}
    .lane>b{font:700 13px Arial,Helvetica,sans-serif}
    .lane ol{margin:.35rem 0;padding-left:1.3rem}
    .lane li{font:13px/1.43 Arial,Helvetica,sans-serif;margin:.2rem 0}
    .attack-flow{padding-left:1.45rem;margin:.25rem 0}
    .attack-flow li{padding:.25rem 0;border-bottom:1px dotted #bbb;font:13px/1.45 Arial,Helvetica,sans-serif}
    .attack-flow li:last-child{border:0}
    .footnote{font:12px/1.45 Arial,Helvetica,sans-serif;color:var(--muted);margin-top:2.6rem;border-top:1px solid var(--rule);padding-top:.7rem;text-align:left}
    @media(max-width:680px){.page{padding:26px 19px}.cover{min-height:260px}.roles{flex-wrap:wrap}.roles div{flex:1 1 28%}.roles>span{display:none}table{display:block;overflow:auto}}
    @media(max-width:420px){.roles div{flex:1 1 45%}}
    @media print{@page{size:A4;margin:18mm}body{background:#fff;font-size:11pt}.page{max-width:none;margin:0;padding:0}.cover{min-height:220mm;break-after:page;border:0;margin:0;padding:0}.toc{break-after:page}h2,h3,h4{break-after:avoid}p,li{orphans:3;widows:3}.diagram,.code-block,table{break-inside:avoid}a{color:#222;text-decoration:none}}
  </style>
</head>
<body>
  <main class="page">
    <article>${reportBody}</article>
    <p class="footnote">Елаборатот е наменет за локална, изолирана лабораториска употреба. Практичниот код не е продукциска OAuth или JWT имплементација.</p>
  </main>
</body>
</html>
`;

await writeFile(outputPath, html, 'utf8');
console.log(`Created ${outputPath}`);
