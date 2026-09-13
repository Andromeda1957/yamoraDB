import concurrent.futures
import gzip
import http.client
import json
import os
import re
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'build' / 'yamldb'


class ProductionDaemonTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temporary.name) / 'data'
        collection = self.data_dir / 'players'
        collection.mkdir(parents=True)
        self.payload = (
            b'schema_version: 1\nkind: study-player\nid: player-one\n'
            + b'biography: |\n  cached and compressible\n' * 100
        )
        (collection / 'player-one.yaml').write_bytes(self.payload)
        self.process = None

    def tearDown(self):
        self.stop()
        self.temporary.cleanup()

    def start(self, *arguments):
        self.process = subprocess.Popen(
            [
                str(BINARY),
                '--data-dir',
                str(self.data_dir),
                '--port',
                '0',
                *arguments,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = self.process.stdout.readline().strip()
        match = re.match(r'^yamldb listening on 127\.0\.0\.1:(\d+) revision=([0-9a-f]{16}) ', line)
        self.assertIsNotNone(match, line)
        self.port = int(match.group(1))
        self.revision = match.group(2)

    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                self.process.wait(timeout=4)
            self.process.stdout.close()
            self.process.stderr.close()
            self.process = None

    def request(self, path, *, method='GET', headers=None, body=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        body = response.read()
        result = response.status, dict(response.getheaders()), body
        connection.close()
        return result

    def test_readiness_stats_metrics_collections_and_cached_gzip(self):
        self.start()
        status, headers, body = self.request('/readyz')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['revision'], self.revision)
        self.assertEqual(headers['X-YamlDB-Revision'], self.revision)

        status, _, body = self.request('/v1/collections')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {'collections': ['players']})

        status, headers, body = self.request(
            '/v1/collections/players/documents/player-one',
            headers={'Accept-Encoding': 'gzip'},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers['Content-Encoding'], 'gzip')
        self.assertEqual(headers['Vary'], 'Accept-Encoding')
        self.assertEqual(gzip.decompress(body), self.payload)
        self.assertLess(len(body), len(self.payload))

        status, _, body = self.request('/v1/stats')
        stats = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(stats['documents'], 1)
        self.assertGreaterEqual(stats['responses_2xx'], 3)
        self.assertGreater(stats['compressed_bytes'], 0)

        status, _, body = self.request('/metrics')
        self.assertEqual(status, 200)
        self.assertIn(b'yamldb_overload_rejections_total', body)
        self.assertIn(b'yamldb_snapshot_compressed_bytes', body)

    def test_authentication_protects_everything_except_liveness(self):
        token = 'a-secure-test-token-with-at-least-32-bytes'
        token_path = Path(self.temporary.name) / 'token'
        token_path.write_text(token + '\n', encoding='ascii')
        token_path.chmod(0o440)
        self.start('--auth-token-file', str(token_path))

        self.assertEqual(self.request('/healthz')[0], 200)
        status, headers, _ = self.request('/readyz')
        self.assertEqual(status, 401)
        self.assertEqual(headers['WWW-Authenticate'], 'Bearer')
        self.assertEqual(
            self.request('/readyz', headers={'Authorization': 'Bearer wrong'})[0],
            401,
        )
        status, _, body = self.request(
            '/readyz',
            headers={'Authorization': f'Bearer {token}'},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['status'], 'ready')

    def test_authentication_rejects_writable_or_public_token_permissions(self):
        token_path = Path(self.temporary.name) / 'insecure-token'
        token_path.write_text(
            'a-secure-test-token-with-at-least-32-bytes\n',
            encoding='ascii',
        )
        for mode in (0o660, 0o700, 0o644, 0o444):
            with self.subTest(mode=oct(mode)):
                token_path.chmod(mode)
                result = subprocess.run(
                    [
                        str(BINARY),
                        '--data-dir',
                        str(self.data_dir),
                        '--port',
                        '0',
                        '--auth-token-file',
                        str(token_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    check=False,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn('authentication token file is invalid', result.stderr)

    def test_concurrent_cached_reads_complete_without_errors(self):
        self.start('--workers', '8', '--queue-capacity', '128')
        path = '/v1/collections/players/documents/player-one'

        def fetch(_):
            return self.request(path)[0:3:2]

        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
            results = list(executor.map(fetch, range(512)))
        elapsed = time.perf_counter() - started
        self.assertTrue(all(status == 200 and body == self.payload for status, body in results))
        self.assertLess(elapsed, 5)

    def test_absolute_targets_bodies_duplicate_headers_and_slowloris_fail_closed(self):
        self.start('--io-timeout-ms', '200')
        cases = (
            b'GET http://127.0.0.1/internal HTTP/1.1\r\nHost: localhost\r\n\r\n',
            b'GET /readyz HTTP/1.1\r\n\r\n',
            b'GET /readyz HTTP/1.1\r\nHost: one\r\nHost: two\r\n\r\n',
            b'GET /readyz HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx',
        )
        for raw in cases:
            with self.subTest(raw=raw):
                with socket.create_connection(('127.0.0.1', self.port), timeout=2) as client:
                    client.sendall(raw)
                    response = client.recv(4096)
                self.assertIn(b' 400 ', response)

        with socket.create_connection(('127.0.0.1', self.port), timeout=2) as client:
            client.sendall(b'GET /readyz HTTP/1.1\r\n')
            time.sleep(0.3)
            response = client.recv(4096)
        self.assertIn(b' 408 ', response)
        self.assertEqual(self.request('/healthz')[0], 200)

    def test_bounded_queue_rejects_overload_and_recovers(self):
        self.start('--workers', '1', '--queue-capacity', '1', '--io-timeout-ms', '1000')
        first = socket.create_connection(('127.0.0.1', self.port), timeout=2)
        first.sendall(b'GET /readyz HTTP/1.1\r\n')
        time.sleep(0.1)
        second = socket.create_connection(('127.0.0.1', self.port), timeout=2)
        second.sendall(b'GET /readyz HTTP/1.1\r\n')
        time.sleep(0.1)
        with socket.create_connection(('127.0.0.1', self.port), timeout=2) as third:
            third.sendall(b'GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n')
            response = third.recv(4096)
        first.close()
        second.close()
        self.assertIn(b' 503 ', response)
        time.sleep(1.1)
        self.assertEqual(self.request('/healthz')[0], 200)

    def test_startup_rejects_symlink_invalid_utf8_and_oversized_documents(self):
        variants = ('symlink', 'utf8', 'oversized')
        for variant in variants:
            with self.subTest(variant=variant):
                path = self.data_dir / 'players' / 'invalid.yaml'
                if variant == 'symlink':
                    outside = Path(self.temporary.name) / 'outside.yaml'
                    outside.write_text('secret: true\n', encoding='utf-8')
                    os.symlink(outside, path)
                elif variant == 'utf8':
                    path.write_bytes(b'name: \xff\n')
                else:
                    path.write_bytes(b'x' * (256 * 1024 + 1))
                result = subprocess.run(
                    [str(BINARY), '--data-dir', str(self.data_dir), '--validate-only'],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    check=False,
                )
                self.assertEqual(result.returncode, 1)
                if path.is_symlink() or path.exists():
                    path.unlink()

    def test_snapshot_indexes_and_pages_thousands_of_documents(self):
        projected_event_count = 5_252
        events = self.data_dir / 'events'
        events.mkdir()
        for index in range(projected_event_count):
            (events / f'event-{index:05d}.yaml').write_text(
                f'id: event-{index:05d}\n',
                encoding='utf-8',
            )

        result = subprocess.run(
            [str(BINARY), '--data-dir', str(self.data_dir), '--validate-only'],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['documents'], projected_event_count + 1)

        self.start('--workers', '8', '--queue-capacity', '128')
        documents = []
        after = None
        while True:
            query = '?limit=1000'
            if after is not None:
                query += f'&after={after}'
            status, _, body = self.request(
                f'/v1/collections/events/documents{query}',
            )
            self.assertEqual(status, 200, body)
            page = json.loads(body)
            documents.extend(page['documents'])
            after = page['next_after']
            if after is None:
                break
        self.assertEqual(len(documents), projected_event_count)
        self.assertEqual(documents[0], 'event-00000')
        self.assertEqual(documents[-1], f'event-{projected_event_count - 1:05d}')

        sample_indexes = range(0, projected_event_count, 37)
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as executor:
            samples = list(executor.map(
                lambda index: self.request(
                    f'/v1/collections/events/documents/event-{index:05d}',
                )[0],
                sample_indexes,
            ))
        self.assertTrue(all(status == 200 for status in samples))

    def test_native_compressor_round_trips_varied_yaml_payloads(self):
        patterns = {
            'single-byte-runs': b'notes: |\n  ' + b'a' * 12_000 + b'\n',
            'short-distance': (
                b'notes: |\n  ' + (b'abcdefghijklmno' * 1_500) + b'\n'
            ),
            'structured-lines': (
                b'items:\n' +
                b''.join(
                    f'  - id: event-{index % 97:03d}\n    year: {1886 + index % 140}\n'.encode()
                    for index in range(2_000)
                )
            ),
            'long-distance': (
                b'notes: |\n  ' +
                bytes(33 + ((index * 73 + index // 11) % 90) for index in range(32_000)) * 2 +
                b'\n'
            ),
            'unicode': ('notes: |\n  José Capablanca — '.encode() * 1_000),
        }
        for name, payload in patterns.items():
            (self.data_dir / 'players' / f'{name}.yaml').write_bytes(payload)
        self.start()

        for name, payload in patterns.items():
            with self.subTest(name=name):
                status, headers, body = self.request(
                    f'/v1/collections/players/documents/{name}',
                    headers={'Accept-Encoding': 'gzip'},
                )
                self.assertEqual(status, 200)
                self.assertEqual(headers.get('Content-Encoding'), 'gzip')
                self.assertLess(len(body), len(payload))
                self.assertEqual(gzip.decompress(body), payload)

    def test_native_writes_fail_closed_on_malformed_input_and_disabled_mode(self):
        path = '/v1/collections/notes/documents/first'
        payload = b'id: first\nnotes: native storage\n'
        self.start()
        self.assertEqual(self.request(
            path,
            method='PUT',
            body=payload,
            headers={'Content-Type': 'application/yaml'},
        )[0], 405)
        self.assertFalse((self.data_dir / 'notes').exists())
        self.stop()

        write_token = 'write-token-with-at-least-thirty-two-bytes'
        token_path = Path(self.temporary.name) / 'write-token'
        token_path.write_text(write_token + '\n', encoding='ascii')
        token_path.chmod(0o600)
        self.start('--write-auth-token-file', str(token_path))
        authorization = {'Authorization': f'Bearer {write_token}'}
        self.assertEqual(self.request(
            path,
            method='PUT',
            body=b'id: \xff\n',
            headers={**authorization, 'Content-Type': 'application/yaml'},
        )[0], 400)
        self.assertEqual(self.request(
            path,
            method='PUT',
            body=payload,
            headers={**authorization, 'Content-Type': 'application/json'},
        )[0], 415)
        status, _, body = self.request(
            path,
            method='PUT',
            body=payload,
            headers={
                **authorization,
                'Content-Type': 'application/yaml',
                'If-None-Match': '*',
            },
        )
        self.assertEqual(status, 201, body)
        self.assertEqual(self.request(
            path, method='DELETE', headers=authorization,
        )[0], 204)
        self.stop()
        self.start('--write-auth-token-file', str(token_path))
        self.assertEqual(self.request(path)[0], 404)
        self.assertIn('notes', json.loads(self.request('/v1/collections')[2])['collections'])

    def test_empty_collections_and_interrupted_write_temporaries_recover(self):
        (self.data_dir / 'empty').mkdir()
        temporary = self.data_dir / 'players' / '.yamldb-123-456-789'
        temporary.write_bytes(b'partial write that must never become visible')
        result = subprocess.run(
            [str(BINARY), '--data-dir', str(self.data_dir), '--validate-only'],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.start()
        self.assertEqual(
            json.loads(self.request('/v1/collections')[2])['collections'],
            ['empty', 'players'],
        )
        self.assertEqual(
            json.loads(self.request('/v1/collections/empty/documents')[2]),
            {'collection': 'empty', 'documents': []},
        )
        self.assertEqual(
            json.loads(self.request('/v1/collections/players/documents')[2])['documents'],
            ['player-one'],
        )

    def test_concurrent_native_writes_publish_consistent_read_snapshots(self):
        write_token = 'write-token-with-at-least-thirty-two-bytes'
        token_path = Path(self.temporary.name) / 'write-token'
        token_path.write_text(write_token + '\n', encoding='ascii')
        token_path.chmod(0o600)
        self.start(
            '--write-auth-token-file', str(token_path),
            '--workers', '8',
            '--queue-capacity', '128',
        )
        headers = {
            'Authorization': f'Bearer {write_token}',
            'Content-Type': 'application/yaml',
            'If-None-Match': '*',
        }

        def create(index):
            document = f'note-{index:02d}'
            payload = f'id: {document}\nvalue: {index}\n'.encode()
            return self.request(
                f'/v1/collections/notes/documents/{document}',
                method='PUT',
                body=payload,
                headers=headers,
            )[0]

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
            statuses = list(executor.map(create, range(24)))
        self.assertEqual(statuses, [201] * 24)
        status, _, body = self.request(
            '/v1/collections/notes/documents?limit=100',
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(len(json.loads(body)['documents']), 24)
        self.stop()
        self.start('--write-auth-token-file', str(token_path))
        self.assertEqual(self.request(
            '/v1/collections/notes/documents/note-23',
        )[2], b'id: note-23\nvalue: 23\n')

    def test_maximum_write_and_partial_body_timeouts_release_resources(self):
        write_token = 'write-token-with-at-least-thirty-two-bytes'
        token_path = Path(self.temporary.name) / 'write-token'
        token_path.write_text(write_token + '\n', encoding='ascii')
        token_path.chmod(0o600)
        self.start(
            '--write-auth-token-file', str(token_path),
            '--io-timeout-ms', '200',
        )
        authorization = f'Bearer {write_token}'
        prefix = b'notes: |\n  '
        maximum_payload = prefix + b'x' * (256 * 1024 - len(prefix))
        path = '/v1/collections/players/documents/maximum'
        status, _, body = self.request(
            path,
            method='PUT',
            body=maximum_payload,
            headers={
                'Authorization': authorization,
                'Content-Type': 'application/yaml',
                'If-None-Match': '*',
            },
        )
        self.assertEqual(status, 201, body)
        status, headers, body = self.request(
            path, headers={'Accept-Encoding': 'gzip'},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get('Content-Encoding'), 'gzip')
        self.assertEqual(gzip.decompress(body), maximum_payload)

        request = (
            b'PUT /v1/collections/players/documents/partial HTTP/1.1\r\n'
            b'Host: localhost\r\n'
            + f'Authorization: {authorization}\r\n'.encode()
            + b'Content-Type: application/yaml\r\n'
            + b'Content-Length: 100\r\n\r\nshort'
        )
        for _ in range(12):
            with socket.create_connection(('127.0.0.1', self.port), timeout=2) as client:
                client.sendall(request)
                time.sleep(0.22)
                response = client.recv(4096)
            self.assertIn(b' 408 ', response)
        with socket.create_connection(('127.0.0.1', self.port), timeout=2) as client:
            client.sendall(
                b'PUT /v1/collections/players/documents/oversized HTTP/1.1\r\n'
                b'Host: localhost\r\n'
                + f'Authorization: {authorization}\r\n'.encode()
                + b'Content-Type: application/yaml\r\n'
                + b'Content-Length: 262145\r\n\r\n'
            )
            response = client.recv(4096)
        self.assertIn(b' 413 ', response)
        self.assertEqual(self.request('/healthz')[0], 200)

    def test_read_and_write_credentials_must_be_distinct(self):
        token = 'one-token-with-at-least-thirty-two-bytes'
        read_path = Path(self.temporary.name) / 'read-token'
        write_path = Path(self.temporary.name) / 'write-token'
        read_path.write_text(token + '\n', encoding='ascii')
        write_path.write_text(token + '\n', encoding='ascii')
        read_path.chmod(0o600)
        write_path.chmod(0o600)
        result = subprocess.run(
            [
                str(BINARY), '--data-dir', str(self.data_dir), '--port', '0',
                '--auth-token-file', str(read_path),
                '--write-auth-token-file', str(write_path),
            ],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn('read and write tokens must differ', result.stderr)

    def test_bind_address_rejects_wildcard_public_and_unauthenticated_lan(self):
        cases = (
            ('0.0.0.0', 2, 'numeric loopback or RFC1918'),
            ('169.254.169.254', 2, 'numeric loopback or RFC1918'),
            ('8.8.8.8', 2, 'numeric loopback or RFC1918'),
            ('192.168.10.20', 1, 'authentication token is required'),
        )
        for address, returncode, message in cases:
            with self.subTest(address=address):
                result = subprocess.run(
                    [
                        str(BINARY), '--data-dir', str(self.data_dir),
                        '--bind-address', address, '--port', '0',
                    ],
                    capture_output=True,
                    text=True,
                    timeout=4,
                    check=False,
                )
                self.assertEqual(result.returncode, returncode)
                self.assertIn(message, result.stderr)

    def test_native_c_daemon_crud_is_atomic_guarded_and_restart_durable(self):
        read_token = 'read-token-with-at-least-thirty-two-bytes'
        write_token = 'write-token-with-at-least-thirty-two-bytes'
        read_token_path = Path(self.temporary.name) / 'read-token'
        write_token_path = Path(self.temporary.name) / 'write-token'
        read_token_path.write_text(read_token + '\n', encoding='ascii')
        write_token_path.write_text(write_token + '\n', encoding='ascii')
        read_token_path.chmod(0o600)
        write_token_path.chmod(0o600)
        arguments = (
            '--auth-token-file', str(read_token_path),
            '--write-auth-token-file', str(write_token_path),
        )
        self.start(*arguments)
        path = '/v1/collections/players/documents/player-two'
        payload = b'schema_version: 1\nkind: study-player\nid: player-two\nname: Player Two\n'
        write_headers = {
            'Authorization': f'Bearer {write_token}',
            'Content-Type': 'application/yaml',
            'If-None-Match': '*',
        }

        self.assertEqual(self.request(
            path,
            method='PUT',
            body=payload,
            headers={
                'Authorization': f'Bearer {read_token}',
                'Content-Type': 'application/yaml',
                'If-None-Match': '*',
            },
        )[0], 401)
        status, headers, body = self.request(
            path, method='PUT', body=payload, headers=write_headers,
        )
        self.assertEqual(status, 201, body)
        etag = headers['ETag']

        self.assertEqual(self.request(
            path, method='PUT', body=payload, headers=write_headers,
        )[0], 412)
        replacement = payload.replace(b'Player Two', b'Player 2')
        status, headers, body = self.request(
            path,
            method='PUT',
            body=replacement,
            headers={
                'Authorization': f'Bearer {write_token}',
                'Content-Type': 'application/yaml',
                'If-Match': etag,
            },
        )
        self.assertEqual(status, 200, body)
        replacement_etag = headers['ETag']
        self.assertNotEqual(replacement_etag, etag)

        self.stop()
        self.start(*arguments)
        status, _, body = self.request(
            path, headers={'Authorization': f'Bearer {read_token}'},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, replacement)

        status, _, body = self.request(
            path,
            method='DELETE',
            headers={
                'Authorization': f'Bearer {write_token}',
                'If-Match': replacement_etag,
            },
        )
        self.assertEqual(status, 204, body)
        self.assertEqual(self.request(
            path, headers={'Authorization': f'Bearer {read_token}'},
        )[0], 404)

    def test_document_indexes_support_bounded_cursor_pages(self):
        for index in range(25):
            (self.data_dir / 'players' / f'player-{index:02d}.yaml').write_text(
                f'id: player-{index:02d}\n', encoding='utf-8',
            )
        self.start()
        status, _, body = self.request(
            '/v1/collections/players/documents?limit=10&after=player-08',
        )
        self.assertEqual(status, 200, body)
        page = json.loads(body)
        self.assertEqual(
            page['documents'],
            [f'player-{index:02d}' for index in range(9, 19)],
        )
        self.assertEqual(page['next_after'], 'player-18')

    def test_sigterm_is_graceful_and_successful(self):
        self.start()
        self.process.terminate()
        returncode = self.process.wait(timeout=4)
        self.assertEqual(returncode, 0)


if __name__ == '__main__':
    unittest.main()
