"""Ejecutar después de dotnet build; no usa paquetes Python externos."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.request

root = Path(__file__).resolve().parents[1]
with socket.socket() as reservation:
    reservation.bind(('127.0.0.1', 0))
    port = reservation.getsockname()[1]
base = f'http://127.0.0.1:{port}'
key = secrets.token_hex(32)
env = dict(os.environ, ApiKey__Key=key, ApiKey__ActorId='smoke-service', ASPNETCORE_URLS=base)
process = subprocess.Popen(['dotnet', str(root / 'Api/bin/Debug/net10.0/Api.dll')],
                           cwd=root / 'Api', env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

def request(path, body=None, authenticated=True):
    headers = {'Content-Type': 'application/json'}
    if authenticated:
        headers['X-Api-Key'] = key if authenticated is True else authenticated
    payload = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None, response.headers
    except urllib.error.HTTPError as error:
        return error.code, None, error.headers

body = dict(externalId='smoke-1', userId='test-001', operation='Create',
            roles=['Operator'], expectedVersion=0, reason='HTTP smoke test')
try:
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError('API terminó durante el arranque')
        try:
            if request('/api/v1/audit')[0] == 200:
                break
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.1)
    else:
        raise RuntimeError('API no inició')
    assert request('/api/v1/requests', {}, False)[0] == 401
    assert request('/api/v1/requests', body, 'wrong-key')[0] == 401
    assert request('/api/v1/requests', body, key + ',' + key)[0] == 401
    status, receipt, headers = request('/api/v1/requests', body)
    assert status == 202 and receipt['status'] == 'Pending'
    assert headers['Location'] == '/api/v1/requests/' + receipt['id']
    assert request(headers['Location'])[1]['id'] == receipt['id']
    assert request('/api/v1/requests', body)[1]['id'] == receipt['id']
    assert request('/api/v1/requests', dict(body, reason='Changed'))[0] == 409
    assert request('/api/v1/requests', dict(body, roles=['Unknown']))[0] == 400
    assert request('/api/v1/requests', dict(body, roles=[1]))[0] == 400
    assert request('/api/v1/requests', dict(body, roles=None))[0] == 400
    assert request('/api/v1/requests', dict(body, operation=None))[0] == 400
    assert request('/api/v1/requests', dict(body, actorId='spoofed'))[0] == 400
    missing = dict(body)
    del missing['expectedVersion']
    assert request('/api/v1/requests', missing)[0] == 400
    status, denied, headers = request('/api/v1/requests', dict(body, externalId='smoke-denied',
        roles=['Operator', 'Approver']))
    assert status == 202 and denied['status'] == 'Rejected'
    assert denied['rejectionCode'] == 'SOD_OPERATOR_APPROVER'
    assert request(headers['Location'])[1]['status'] == 'Rejected'
    assert request('/api/v1/requests/00000000-0000-0000-0000-000000000000')[0] == 404

    def submit(i):
        status, result, _ = request('/api/v1/requests', dict(body, externalId=f'parallel-{i}'))
        assert status == 202
        return result['id']

    with ThreadPoolExecutor(max_workers=12) as pool:
        unique = list(pool.map(submit, range(60)))
        repeated = list(pool.map(lambda _: submit('same'), range(60)))
    assert len(set(unique)) == 60 and len(set(repeated)) == 1
    events = request('/api/v1/audit')[1]
    assert len(events) == 63
    previous = '0' * 64
    for sequence, event in enumerate(events, 1):
        assert event['sequence'] == sequence and event['previousHash'] == previous
        assert event['actorId'] == 'smoke-service'
        assert event['before'] is None and event['after'] is None
        stored_hash = event['hash']
        event['hash'] = ''
        payload = json.dumps(event, separators=(',', ':'), ensure_ascii=True).encode()
        assert hashlib.sha256(payload).hexdigest().upper() == stored_hash
        previous = stored_hash
    print('PASS: HTTP 401/400/404/409/202, Location, Pending/Rejected, identidad, idempotencia y concurrencia')
    print('PASS: 63 eventos con cadena SHA-256 recalculada independientemente desde Python')
finally:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
