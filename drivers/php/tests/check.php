<?php
declare(strict_types=1);

require_once __DIR__ . '/../src/Client.php';

use Yamora\Client;
use Yamora\DeadlineException;
use Yamora\HttpException;
use Yamora\ProtocolException;
use Yamora\TlsOptions;
use Yamora\TransportException;

function same(mixed $actual, mixed $expected): void
{
    if ($actual !== $expected) {
        throw new RuntimeException('Unexpected result: ' . var_export($actual, true) . ' expected ' . var_export($expected, true));
    }
}

function fails(callable $action, string $type, ?int $status = null): void
{
    try {
        $action();
    } catch (Throwable $error) {
        if (!$error instanceof $type) { throw $error; }
        if ($status !== null) { same($error->status, $status); }
        return;
    }
    throw new RuntimeException('Expected ' . $type);
}

function client(?TlsOptions $tls = null, float $timeout = 2.0, int $maximum = Client::MAX_RESPONSE_BYTES): Client
{
    return new Client(port: (int) getenv('TEST_PORT'), readToken: str_repeat('r', 32),
        writeToken: str_repeat('w', 32), tls: $tls, timeout: $timeout, maxResponseBytes: $maximum);
}

function tlsReadError(TlsOptions $tls): void
{
    $warnings = 0;
    set_error_handler(static function () use (&$warnings): bool { ++$warnings; return true; });
    try {
        try {
            client($tls)->health();
            throw new RuntimeException('Expected TLS read failure');
        } catch (TransportException $error) {
            same($error->getMessage(), 'yamora: response read failed');
        }
        same($warnings, 0);
        trigger_error('synthetic application warning', E_USER_WARNING);
        same($warnings, 1);
    } finally {
        restore_error_handler();
    }
}

function validation(): void
{
    foreach (['localhost', 'http://127.0.0.1', '127.0.0.1/evil', '127.1', '0177.0.0.1',
        '127.00.0.1', '127.0.0.1 ', "127.0.0.1\n", '0.0.0.0', '8.8.8.8', '169.254.169.254',
        '100.64.0.1', '172.32.0.1', '192.169.0.1', '::1', '::ffff:127.0.0.1'] as $host) {
        fails(fn() => new Client(host: $host), InvalidArgumentException::class);
    }
    foreach (['127.2.3.4', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1'] as $host) {
        new Client(host: $host);
    }
    foreach ([0, -1, 65536] as $port) { fails(fn() => new Client(port: $port), InvalidArgumentException::class); }
    foreach ([0.0, -1.0, 31.0, INF, NAN] as $timeout) { fails(fn() => new Client(timeout: $timeout), InvalidArgumentException::class); }
    foreach (['short', str_repeat('t', 513), str_repeat('t', 31) . "\r\n", str_repeat('t', 31) . ' ', str_repeat('t', 31) . "\x80"] as $token) {
        fails(fn() => new Client(readToken: $token), InvalidArgumentException::class);
        fails(fn() => new Client(writeToken: $token), InvalidArgumentException::class);
    }
    $c = new Client(port: 1);
    foreach (['', '../secret', 'a/b', 'a%2fb', 'Upper', 'a?x=1', 'a#frag', "a\r\nX: y", str_repeat('a', 129)] as $id) {
        fails(fn() => $c->get($id, 'ok'), InvalidArgumentException::class);
        fails(fn() => $c->get('ok', $id), InvalidArgumentException::class);
    }
    fails(fn() => $c->put('a', 'b', ''), InvalidArgumentException::class);
    fails(fn() => $c->put('a', 'b', "text: \xff"), InvalidArgumentException::class);
    fails(fn() => $c->put('a', 'b', str_repeat('a', Client::MAX_DOCUMENT_BYTES + 1)), InvalidArgumentException::class);
    fails(fn() => $c->put('a', 'b', 'x: 1', '0123456789abcdef', true), InvalidArgumentException::class);
    fails(fn() => $c->delete('a', 'b', '"0123456789abcdef"'), InvalidArgumentException::class);
    fails(fn() => $c->patch('a', 'b', []), InvalidArgumentException::class);
    foreach ([str_repeat('0', 32), str_repeat('A', 32), "123\r\nfoo"] as $id) {
        fails(fn() => $c->put('a', 'b', 'x: 1', requestId: $id), InvalidArgumentException::class);
    }
    foreach ([['limit' => 0], ['after' => 'a'], ['limit' => 1001], ['revision' => 'BAD']] as $spec) {
        fails(fn() => $c->query('a', $spec), InvalidArgumentException::class);
    }
    fails(fn() => $c->query('a', ['filter' => ['bad' => "\xff"]]), InvalidArgumentException::class);
    fails(fn() => $c->query('a', ['filter' => ['bad' => INF]]), InvalidArgumentException::class);
    $deep = null;
    for ($i = 0; $i < 70; ++$i) { $deep = [$deep]; }
    fails(fn() => $c->query('a', ['filter' => $deep]), InvalidArgumentException::class);
    fails(fn() => $c->query('a', ['filter' => ['bad' => new DateTime()]]), InvalidArgumentException::class);
    fails(fn() => $c->query('a', ['filter' => ['big' => str_repeat('x', 2 * 1024 * 1024)]]), InvalidArgumentException::class);
    $cycle = new stdClass(); $cycle->self = $cycle;
    fails(fn() => $c->patch('a', 'b', $cycle), InvalidArgumentException::class);
    fails(fn() => $c->transaction([]), InvalidArgumentException::class);
    $op = ['collection' => 'a', 'document' => 'b', 'put' => 'x: 1'];
    fails(fn() => $c->transaction([$op, $op]), InvalidArgumentException::class);
    fails(fn() => $c->transaction([array_merge($op, ['delete' => true])]), InvalidArgumentException::class);
    fails(fn() => $c->transaction([['collection' => 'a', 'document' => 'b', 'delete' => false]]), InvalidArgumentException::class);
    fails(fn() => $c->changes("v1.x\r\n"), InvalidArgumentException::class);
    fails(fn() => $c->documentPage('a', after: 'b'), InvalidArgumentException::class);
    fails(fn() => $c->indexBuild('../x'), InvalidArgumentException::class);
    fails(fn() => new TlsOptions(certificateFile: __FILE__), InvalidArgumentException::class);
    fails(fn() => new TlsOptions(caFile: '/file-does-not-exist'), InvalidArgumentException::class);
}

function native(?TlsOptions $tls): void
{
    $c = client($tls);
    same($c->health()->status, 'ok');
    same($c->ready()->storage, 'native-disk-v2');
    $c->stats();
    same(str_contains($c->metrics(), 'yamldb_uptime_seconds'), true);
    $checkpoint = $c->changes();
    $source = "# exact source\r\nname: Alpha\r\nn: 9007199254740993 # retain\r\nlabel: café\r\n";
    $created = $c->put('people', 'one', $source, createOnly: true, requestId: str_repeat('1', 32));
    $read = $c->get('people', 'one', $created->revision);
    same($read->source, $source);
    same($read->etag, $created->etag);
    fails(fn() => $c->put('people', 'one', $source, createOnly: true), HttpException::class, 412);
    $changed = $c->patch('people', 'one', ['$inc' => ['n' => 1]], $created->etag);
    same($c->get('people', 'one')->source, str_replace('9007199254740993', '9007199254740994', $source));
    foreach (['put', 'patch', 'delete'] as $action) {
        fails(fn() => match ($action) {
            'put' => $c->put('people', 'one', $source, $created->etag),
            'patch' => $c->patch('people', 'one', ['$inc' => ['n' => 1]], $created->etag),
            'delete' => $c->delete('people', 'one', $created->etag),
        }, HttpException::class, 412);
    }
    fails(fn() => $c->get('people', 'missing'), HttpException::class, 404);
    $readOnly = new Client(port: (int) getenv('TEST_PORT'), readToken: str_repeat('r', 32), tls: $tls);
    fails(fn() => $readOnly->put('people', 'two', 'n: 1'), HttpException::class, 401);
    $badToken = new Client(port: (int) getenv('TEST_PORT'), readToken: str_repeat('b', 32), tls: $tls);
    fails(fn() => $badToken->ready(), HttpException::class, 401);
    $result = $c->query('people', ['filter' => ['name' => 'Alpha'], 'explain' => true]);
    same($result->documents[0]->value->n, 9007199254740994);
    same($result->matched, 1);
    same($c->count('people'), 1);
    same($c->collections()->collections, ['people']);
    same(iterator_to_array($c->documents('people')), ['one']);
    $before = $c->ready()->revision;
    $transaction = $c->transaction([
        ['collection' => 'people', 'document' => 'two', 'put' => "name: Beta\nn: 9223372036854775807\n", 'create_only' => true],
        ['collection' => 'people', 'document' => 'one', 'patch' => ['$set' => ['name' => 'Omega']]],
    ], $before);
    same($transaction->operations, 2);
    same($c->query('people', ['filter' => ['name' => 'Beta']])->documents[0]->value->n, PHP_INT_MAX);
    $beforeRejected = $c->get('people', 'one');
    fails(fn() => $c->transaction([
        ['collection' => 'people', 'document' => 'three', 'put' => 'name: Uncommitted'],
        ['collection' => 'people', 'document' => 'one', 'patch' => ['$inc' => ['n' => 1]], 'etag' => $created->etag],
    ]), HttpException::class, 412);
    fails(fn() => $c->get('people', 'three'), HttpException::class, 404);
    same($c->get('people', 'one')->source, $beforeRejected->source);
    fails(fn() => $c->transaction([['collection' => 'people', 'document' => 'three', 'put' => 'n: 0']], $before), HttpException::class, 412);
    fails(fn() => $c->query('people', ['revision' => $before]), HttpException::class, 412);
    $page = $c->documentPage('people', 1);
    same($page->next_after, 'one');
    same($c->documentPage('people', 1, $page->next_after, $page->revision)->documents, ['two']);
    $c->put('other', 'value', 'n: 1');
    fails(fn() => $c->documentPage('people', 1, $page->next_after, $page->revision), ProtocolException::class);
    $total = $c->aggregate('people', [['$count' => 'total']]);
    same($total->documents[0]->total, 2);
    $changes = $c->changes($checkpoint->next_after);
    same(count($changes->transactions), 4);
    same($changes->transactions[0]->operations[1]->put, $source);
    $catalog = $c->indexes();
    $definitions = [
        ['collection' => 'people', 'name' => 'by-name', 'fields' => ['name'], 'unique' => true],
        ['collection' => 'people', 'name' => 'words', 'fields' => ['$source'], 'type' => 'text', 'unique' => false],
    ];
    $c->setIndexes($definitions, $catalog->revision);
    same(count($c->indexes()->indexes), 2);
    same($c->search('people', 'words', 'exact')->documents[0]->id, 'one');
    fails(fn() => $c->setIndexes([], $catalog->revision), HttpException::class, 412);
    $c->indexBuild();
    $job = $c->startIndexBuild($definitions);
    $deadline = microtime(true) + 5;
    do {
        $job = $c->indexBuild($job->id);
        if ($job->status !== 'running') { break; }
        usleep(20000);
    } while (microtime(true) < $deadline);
    same($job->status, 'succeeded');
    fails(fn() => $c->cancelIndexBuild($job->id), HttpException::class, 409);
    $c->delete('people', 'two', $c->get('people', 'two')->etag);
    same($c->count('people'), 1);
    // A multi-MiB Unicode source must survive the socket and native engine exactly.
    $large = "# large\r\ntext: " . str_repeat('é', 600000) . "\r\n";
    $c->put('payloads', 'large', $large);
    same($c->get('payloads', 'large')->source, $large);
    $c->patch('people', 'one', ['$set' => ['label' => "A\u{0085}B"]]);
    same($c->query('people')->documents[0]->value->label, "A\u{0085}B");
}

$case = $argv[1] ?? '';
$tls = getenv('TEST_CA') ? new TlsOptions(getenv('TEST_CA'),
    getenv('TEST_CERT') ?: null, getenv('TEST_KEY') ?: null) : null;
match ($case) {
    'validation' => validation(),
    'native' => native($tls),
    'success' => same(client($tls)->health()->status, 'ok'),
    'replication-source-allowed' => same(client($tls)->requireReplicationSource()->revision, '0123456789abcdef'),
    'replication-source-policy' => fails(fn() => client($tls)->requireReplicationSource(), Yamora\SchemaPolicyReplicationException::class, 409),
    'replication-source-protocol' => fails(fn() => client($tls)->requireReplicationSource(), ProtocolException::class),
    'protocol' => fails(fn() => client($tls, maximum: 1024)->health(), ProtocolException::class),
    'trailing-body' => fails(fn() => client($tls)->health(), ProtocolException::class),
    'encrypted-key' => fails(fn() => client($tls, 0.15)->health(), TransportException::class),
    'deadline' => fails(fn() => client($tls, 0.15)->health(), DeadlineException::class),
    'write-deadline' => fails(fn() => client($tls, 0.15)->put('a', 'b', 'text: ' . str_repeat('x', 12 * 1024 * 1024)), DeadlineException::class),
    'tls-reject' => fails(fn() => client($tls ?? new TlsOptions())->health(), TransportException::class),
    'tls-read-error' => tlsReadError($tls),
    'mtls-reject' => fails(fn() => client($tls)->health(), Yamora\DriverException::class),
    'http-error' => fails(fn() => client($tls)->health(), HttpException::class, (int) getenv('TEST_STATUS')),
    'mutation-error' => fails(fn() => client($tls)->put('a', 'b', "x: 1\n"), HttpException::class, 307),
    'mutation-truncated' => fails(fn() => client($tls)->put('a', 'b', "x: 1\n"), ProtocolException::class),
    'mutation-protocol' => fails(fn() => client($tls)->put('a', 'b', "x: 1\n"), ProtocolException::class),
    'cancel-job' => same(client($tls)->cancelIndexBuild(str_repeat('1', 32))->cancel_requested, true),
    default => throw new RuntimeException('Unknown test case'),
};
echo $case . " passed\n";
