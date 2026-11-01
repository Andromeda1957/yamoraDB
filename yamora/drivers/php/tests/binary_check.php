<?php
declare(strict_types=1);
require_once (getenv('BINARY_SOURCE') ?: __DIR__ . '/../src') . '/BinaryClient.php';
use Yamora\{BinaryClient, BinaryConfig, BinaryEnvelope, BinaryUncertainException, BinaryStatusException,
    BinaryCodec, CancellationToken, OperationControl, DeadlineException, CancelledException, ProtocolException};

final class BinaryAssertion extends RuntimeException {}
function verify(bool $condition, string $message): void { if (!$condition) { throw new BinaryAssertion($message); } }
$settings = json_decode(getenv('BINARY_CONFIG') ?: '{}', true, 32, JSON_THROW_ON_ERROR);
function config(array $changes = []): BinaryConfig {
    global $settings;
    $s = $changes + $settings;
    return new BinaryConfig($s['host'] ?? '127.0.0.1', $s['port'], $s['serverName'] ?? '127.0.0.1',
        file_get_contents($s['ca']), getenv('TMPDIR'),
        isset($s['cert']) ? file_get_contents($s['cert']) : null,
        isset($s['key']) ? file_get_contents($s['key']) : null, $s['timeout'] ?? 4, $s['maxFrame'] ?? 4096);
}
function control(): OperationControl { return new OperationControl(hrtime(true) / 1e9 + 30); }
function encoded(Yamora\BinaryResponse $r): array { return ['metadata' => $r->metadata, 'body' => base64_encode($r->body)]; }
function failure(Throwable $e): array {
    $out = ['error' => $e::class];
    if ($e instanceof BinaryUncertainException) {
        $out += ['id' => $e->requestId, 'reason' => $e->reason, 'status' => $e->status,
            'envelope' => ['method' => $e->envelope->method, 'collection' => $e->envelope->collection,
            'document' => $e->envelope->document, 'source' => base64_encode($e->envelope->source),
            'ifMatch' => $e->envelope->ifMatch, 'ifNoneMatch' => $e->envelope->ifNoneMatch]];
        verify($e->getPrevious() === null, 'raw failure retained');
    }
    if ($e instanceof BinaryStatusException) { $out['status'] = $e->status; }
    return $out;
}

try {
    $case = $argv[1];
    if ($case === 'hash') {
        foreach (['' => '14650fb0739d0383', 'a' => '44bd8ad473cd9906', "\xff\x80\0" => '6aeee84f16c8c754'] as $source => $expected) {
            verify(BinaryCodec::sourceHash($source, control()) === $expected, 'exact native hash');
        }
        echo "ok\n"; exit(0);
    }
    $db = new BinaryClient(config());
    if ($case === 'key-input' || $case === 'key-accept') {
        try {
            new BinaryConfig('127.0.0.1', $settings['port'], '127.0.0.1', file_get_contents($settings['ca']),
                getenv('TMPDIR'), file_get_contents($settings['cert']), $settings['keyInput']);
            verify($case === 'key-accept', 'non-PEM private key accepted');
        } catch (InvalidArgumentException) { verify($case === 'key-input', 'inline PEM private key rejected'); }
        echo "ok\n"; exit(0);
    }
    if ($case === 'config') {
        $args = ['host' => '127.0.0.1', 'port' => $settings['port'], 'serverName' => '127.0.0.1',
            'caPem' => file_get_contents($settings['ca']), 'privateDirectory' => getenv('TMPDIR')];
        $bad = new class { public function __toString(): string { throw new BinaryAssertion('trust conversion invoked'); } };
        $maxName = implode('.', [str_repeat('a', 63), str_repeat('b', 63), str_repeat('c', 63), str_repeat('d', 61)]);
        foreach (['localhost', 'LOCALHOST', 'server.example', $maxName] as $name) {
            new BinaryConfig(...(['serverName' => $name] + $args));
        }
        foreach ([['host' => 'localhost'], ['host' => '8.8.8.8'], ['host' => '0127.0.0.1'], ['host' => '169.254.169.254'],
            ['port' => '7401'], ['serverName' => '127.00.0.1'], ['serverName' => '8.8.8.8'],
            ['serverName' => ''], ['serverName' => '*.example'], ['serverName' => 'server_name'],
            ['serverName' => '-start.example'], ['serverName' => 'end-.example'], ['serverName' => 'trailing.example.'],
            ['serverName' => 'a..b'], ['serverName' => str_repeat('a', 64) . '.test'], ['serverName' => $maxName . 'x'],
            ['serverName' => "localhost\0wrong"], ['serverName' => "localhost\r\n"], ['serverName' => $bad],
            ['caPem' => $bad], ['caPem' => "bad"], ['caPem' => file_get_contents($settings['cert'])],
            ['clientCertPem' => file_get_contents($settings['cert'])], ['timeout' => NAN], ['maxFrame' => 4095],
            ['maxFrame' => 65537], ['privateDirectory' => $settings['sharedDirectory']],
            ['clientCertPem' => file_get_contents($settings['cert']), 'clientKeyPem' => file_get_contents($settings['encrypted'])],
            ['clientCertPem' => file_get_contents($settings['cert']), 'clientKeyPem' => file_get_contents($settings['wrongKey'])]] as $badConfig) {
            try { new BinaryConfig(...($badConfig + $args)); verify(false, 'invalid trust config accepted'); }
            catch (InvalidArgumentException) {}
        }
        echo "ok\n"; exit(0);
    }
    if ($case === 'rpc') {
        $saved = [];
        while (($line = fgets(STDIN)) !== false) {
            try {
                $command = json_decode($line, true, 32, JSON_THROW_ON_ERROR);
                $method = $command['method']; $args = $command['args'];
                if ($method === 'recover') {
                    $first = $saved[$args['id']]; unset($args['id']);
                    $r = $db->recover($first, ...$args);
                } else { $r = $db->$method(...$args); }
                echo json_encode(['ok' => encoded($r)], JSON_THROW_ON_ERROR), "\n";
            } catch (Throwable $e) {
                if ($e instanceof BinaryUncertainException) { $saved[$e->requestId] = $e; }
                echo json_encode(failure($e), JSON_THROW_ON_ERROR), "\n";
            }
            flush();
        }
    } elseif ($case === 'uncertain' || $case === 'protocol') {
        try {
            $method = $settings['method'] ?? 'put';
            $args = ['a', 'b'];
            if ($method === 'put') { $args[] = "n: 1\n"; }
            $db->$method(...[...$args, 'token' => str_repeat('w', 32), 'requestId' => $settings['id'] ?? null,
                'ifMatch' => $settings['ifMatch'] ?? null, 'ifNoneMatch' => $settings['ifNoneMatch'] ?? null]);
            verify(false, $case === 'uncertain' ? 'ambiguous receipt accepted' : 'hostile read accepted');
        } catch (BinaryUncertainException $e) {
            verify($case === 'uncertain', 'read became mutation uncertainty');
            verify($e->envelope->source === "n: 1\n" || $e->envelope->method === 'DELETE', 'operation source lost');
            echo json_encode(failure($e)), "\n";
        } catch (ProtocolException $e) { verify($case === 'protocol', 'mutation uncertainty lost'); echo "ok\n"; }
    } elseif ($case === 'ownership') {
        $source = "n: 1\n"; $token = str_repeat('w', 32); $pem = file_get_contents($settings['ca']);
        $cfg = new BinaryConfig('127.0.0.1', $settings['port'], '127.0.0.1', $pem, getenv('TMPDIR'),
            file_get_contents($settings['cert']), file_get_contents($settings['key']), maxFrame: 4096);
        $pem = 'destroyed';
        foreach (['ca', 'cert', 'key'] as $key) { file_put_contents($settings[$key], 'destroyed'); }
        $db = new BinaryClient($cfg);
        $attempted = false;
        pcntl_async_signals(true);
        pcntl_signal(SIGUSR1, function () use (&$source, &$token, &$attempted, $db): void {
            $source[0] = 'x'; $token = 'new';
            $attempted = true;
            try { $db->put('a', 'b', new class { public function __toString(): string { throw new BinaryAssertion('caller conversion invoked'); } });
                verify(false, 'reentrant admitted'); } catch (LogicException) {}
        });
        echo "ready\n"; flush();
        $r = $db->put('a', 'b', $source, $token);
        verify($attempted && $source === "x: 1\n", 'ownership signal not observed');
        echo json_encode(encoded($r)), "\n";
    } elseif (in_array($case, ['cancel', 'deadline', 'read-cancel', 'read-deadline', 'hash-cancel', 'hash-deadline'], true)) {
        $cancel = new CancellationToken();
        pcntl_async_signals(true);
        pcntl_signal(SIGUSR1, static function () use ($cancel): void { $cancel->cancel(); });
        echo "ready\n"; flush();
        try {
            if (str_starts_with($case, 'read-') || str_starts_with($case, 'hash-')) {
                $db->get('a', 'b', cancellation: $cancel);
            } else { $db->put('a', 'b', "n: 1\n", cancellation: $cancel); }
            verify(false, 'late success returned');
        } catch (BinaryUncertainException $e) {
            verify(!str_starts_with($case, 'read-') && !str_starts_with($case, 'hash-'), 'read uncertainty');
            verify($e->reason === (str_contains($case, 'cancel') ? CancelledException::class : DeadlineException::class), 'wrong control failure');
            echo "ok\n";
        } catch (CancelledException|DeadlineException $e) {
            verify(str_starts_with($case, 'read-') || str_starts_with($case, 'hash-'), 'dispatched uncertainty lost');
            verify($e::class === (str_contains($case, 'cancel') ? CancelledException::class : DeadlineException::class), 'wrong read control failure');
            echo "ok\n";
        }
    } elseif ($case === 'independent') {
        $other = new BinaryClient(config(['port' => $settings['otherPort']]));
        $cancel = new CancellationToken(); $completed = false;
        pcntl_async_signals(true);
        pcntl_signal(SIGUSR1, function () use ($cancel, $other, &$completed): void {
            $cancel->cancel();
            // Another client can finish while the cancelled owner's socket is
            // still open. Neither admission nor cancellation is process-global.
            $r = $other->put('a', 'independent', "n: 2\n", str_repeat('w', 32));
            $completed = in_array($r->metadata['status'], [200, 201], true);
        });
        echo "ready\n"; flush();
        try { $db->put('a', 'b', "n: 1\n", str_repeat('w', 32), cancellation: $cancel); verify(false, 'cancelled owner returned success'); }
        catch (BinaryUncertainException $e) {
            verify($completed && $e->reason === CancelledException::class && $e->envelope->source === "n: 1\n", 'independent cancellation ownership lost');
        }
        echo "ok\n";
    } elseif ($case === 'admission') {
        $cancel = new CancellationToken(); $cancel->cancel();
        try { $db->put('a', 'b', new stdClass(), cancellation: $cancel); verify(false, 'pre-cancel admitted'); } catch (CancelledException) {}
        $fiber = new Fiber(function () use ($db): void {
            try { $db->put('a', 'b', new stdClass()); verify(false, 'fiber admitted'); } catch (LogicException) {}
        }); $fiber->start();
        $bad = new class { public function __toString(): string { throw new BinaryAssertion('caller conversion invoked'); } };
        foreach ([['collection' => $bad], ['source' => $bad], ['token' => $bad], ['requestId' => str_repeat('0', 32)],
            ['method' => 'PATCH'], ['source' => str_repeat('x', 16777217)], ['ifMatch' => "bad\r\n"], ['timeout' => 0]] as $override) {
            $args = $override + ['method' => 'PUT', 'collection' => 'a', 'document' => 'b', 'source' => "n: 1\n"];
            try { $db->request(...$args); verify(false, 'invalid input admitted'); } catch (InvalidArgumentException) {}
        }
        $env = new BinaryEnvelope('PUT', 'a', 'b', "n: 1\n");
        try { $env->source[0] = 'x'; verify(false, 'mutable envelope'); } catch (Error) {}
        $prior = new BinaryUncertainException($env, 'test');
        try { $db->recover($prior, cancellation: $cancel); verify(false, 'recovery cancelled success'); }
        catch (BinaryUncertainException $e) { verify($e->envelope === $env, 'original envelope lost'); }
        $db->close();
        try { $db->execute($env); verify(false, 'closed admitted'); } catch (LogicException) {}
        echo "ok\n";
    } elseif ($case === 'success') {
        $db->put('a', 'b', "n: 1\n", str_repeat('w',32)); echo "ok\n";
    } else { verify(false, 'unknown probe'); }
} catch (BinaryAssertion $e) {
    echo json_encode(['assertion' => $e->getMessage()]), "\n"; exit(3);
} catch (Throwable $e) {
    echo json_encode(['unexpected' => $e::class, 'message' => $e->getMessage()]), "\n"; exit(4);
}
