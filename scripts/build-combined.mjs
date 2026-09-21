import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const oauth = await readFile(join(root, 'oauth2-elaborat.md'), 'utf8');
const jwt = await readFile(join(root, 'jwt-elaborat.md'), 'utf8');

const oauthStart = oauth.indexOf('## 1. Теоретска основа');
const oauthEnd = oauth.indexOf('## Користена литература');
if (oauthStart < 0 || oauthEnd < oauthStart) throw Error('OAuth source sections not found');

const preface = `# OAuth 2.0 и JWT ранливости

**Проектна задача**  
**Автори:** Љупчо Ангеловски — 221563 (OAuth дел); [име и индекс на коавторот] (JWT дел)  
**Датум:** 20.09.2026

## Апстракт

Елаборатот испитува четири грешки во системи за најава и пристап: OAuth Login CSRF, прифаќање непотпишан JWT, слаба HMAC тајна и забуна меѓу асиметричен и симетричен потпис. За секое сценарио се дадени контролирана локална околина, чекори за репродукција, набљудуван резултат и споредба со заштитена варијанта. Целта е да се покаже каде апликацијата му верува на влез што не смее да ја одредува безбедносната одлука.

## Вовед

Најавата преку надворешен провајдер и токените за пристап се вообичаен дел од современите веб-апликации. OAuth 2.0 го уредува делегирањето пристап, OpenID Connect додава стандардизиран идентитетски слој, а JWT е еден од форматите во кои може да се претстават тврдења. Ниту една од овие технологии не ја заменува проверката на контекстот во кој пристигнал одговорот. Погрешно поврзан OAuth callback или погрешно проверен JWT може да создаде валидна на изглед сесија за погрешен корисник.

Практичниот дел користи две **одвоени**, локални лаборатории. Првата ја демонстрира последицата од callback без параметарот state; втората ги изолира трите JWT грешки. Овие лаборатории не се поврзани во еден продукциски OAuth/OIDC систем. Нивната улога е да овозможат безбедно и повторливо споредување на ранливо и поправено однесување. Сите тестови се насочени кон сервисите приложени со проектот.

`;

const oauthPart = oauth.slice(oauthStart, oauthEnd).trimEnd();
const combined = preface + oauthPart + '\n\n' + jwt.trimStart();
const output = join(root, 'elaborat-oauth-jwt.md');
await writeFile(output, combined, 'utf8');
console.log(`Created ${output}`);
