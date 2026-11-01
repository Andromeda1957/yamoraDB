<?php
declare(strict_types=1);
require_once __DIR__ . '/../src/ClusterClient.php';
use Yamora\{ClusterClient, TlsOptions, PreparedMutation, UncertainWriteException, HttpException, DriverException, CancellationToken, CancelledException, DeadlineException};
function check(bool $v, string $message = 'assertion failed'): void { if (!$v) { throw new RuntimeException($message); } }
$config = json_decode(getenv('CLUSTER_CONFIG') ?: '{}', true, 32, JSON_THROW_ON_ERROR);
function client(array $extra = []): ClusterClient {
    global $config;
    $c = $extra + $config;
    return new ClusterClient($c['seeds'], $c['clusterId'], $c['voters'], new TlsOptions($c['ca'], $c['cert'] ?? null, $c['key'] ?? null),
        str_repeat('r', 32), str_repeat('w', 32), $c['timeout'] ?? 2, $c['attemptTimeout'] ?? 0.4, $c['maximum'] ?? 67108864);
}
function action(ClusterClient $db, string $kind = 'put', ?string $id = null): mixed {
    return match ($kind) {
        'put' => $db->put('a', 'b', "# café\r\nn: 0\r\nwide: 9223372036854775807\r\n", requestId: $id),
        'create' => $db->put('a', 'b', "n: 0\n", createOnly: true, requestId: $id),
        'match' => $db->put('a', 'b', "n: 0\n", etag: '0123456789abcdef', requestId: $id),
        'patch' => $db->patch('a', 'b', ['$inc' => ['n' => 1]], requestId: $id),
        'transaction' => $db->transaction([['collection' => 'a', 'document' => 'c', 'put' => "# tx\r\nn: 9\r\n", 'create_only' => true]], requestId: $id),
        'catalog' => $db->setIndexes([['collection' => 'a', 'name' => 'n', 'fields' => ['n']]], requestId: $id),
        'delete' => $db->delete('a', 'c', requestId: $id),
    };
}
$case = $argv[1];
$db = client();
switch ($case) {
case 'config':
    foreach ([['seeds' => []], ['seeds' => [$config['seeds'][0], $config['seeds'][0]]], ['clusterId' => str_repeat('0',32)],
        ['voters' => 4], ['timeout' => 0], ['attemptTimeout' => 31],
        ['seeds' => [['host' => '8.8.8.8','port'=>8765,'node'=>1]]],
        ['seeds' => [['host' => 'localhost','port'=>8765,'node'=>1]]],
        ['seeds' => [['host' => '127.0.0.1','port'=>8765,'node'=>4]]]] as $bad) {
        try { client($bad); throw new RuntimeException('bad config accepted'); } catch (InvalidArgumentException) {}
    }
    foreach (['startIndexBuild', 'indexBuild', 'cancelIndexBuild', 'replication', 'followReplication', 'continuousChanges'] as $method) {
        try { $db->$method([]); throw new RuntimeException('unsupported accepted'); } catch (HttpException $e) { check($e->status === 405); }
    }
    break;
case 'success':
    $v = action($db, getenv('KIND') ?: 'put', str_repeat('1',32));
    check($v instanceof stdClass || is_string($v));
    break;
case 'reject':
    try { action($db); throw new RuntimeException('untrusted route accepted'); }
    catch (UncertainWriteException) { throw new RuntimeException('untrusted route dispatched'); }
    catch (DriverException) {}
    break;
case 'certain':
    try { action($db, getenv('KIND') ?: 'put'); throw new RuntimeException('rejection accepted'); }
    catch (HttpException $e) { check($e->status === (int)getenv('STATUS')); }
    break;
case 'uncertain':
    try { action($db, getenv('KIND') ?: 'put'); throw new RuntimeException('bad receipt accepted'); }
    catch (UncertainWriteException $e) {
        check($e->requestId !== str_repeat('0',32) && preg_match('/\A[0-9a-f]{32}\z/', $e->requestId) === 1);
        check($e->mutation->requestId === $e->requestId);
        check($e->getPrevious() === null);
        echo json_encode(['id'=>$e->requestId, 'method'=>$e->mutation->method, 'body'=>$e->mutation->body, 'status'=>$e->status], JSON_THROW_ON_ERROR), "\n";
    }
    break;
case 'recover':
case 'recover-cancel':
    try { $db->patch('a','b',['$inc'=>['n'=>1]]); throw new RuntimeException('lost reply accepted'); }
    catch (UncertainWriteException $first) {
        $id = $first->requestId;
        $token = new CancellationToken();
        if ($case === 'recover-cancel') { $token->cancel(); }
        try { $db->recover($first, cancellation:$token); throw new RuntimeException('recovery rejection accepted'); }
        catch (UncertainWriteException $later) { check($later->requestId === $id && ($case === 'recover-cancel' ? $later->reason === CancelledException::class : $later->status === 412)); }
    }
    break;
case 'prepare':
    $value = (object)['n' => 1];
    $ops = ['$inc' => $value];
    $frozen = $db->prepareMutation('patch', ['a','b',$ops, 'requestId'=>str_repeat('2',32)]);
    $value->n = 99; $ops['$set'] = ['x'=>'new'];
    check($frozen->body === '{"$inc":{"n":1}}');
    try { $frozen->headers['If-Match']='new'; throw new RuntimeException('mutable headers'); } catch (Error) {}
    try { $frozen->body='new'; throw new RuntimeException('mutable body'); } catch (Error) {}
    $db->execute($frozen);
    break;
case 'snapshot':
    $value = (object)['n' => 1];
    $token = new CancellationToken();
    pcntl_async_signals(true);
    pcntl_signal(SIGUSR1, function () use ($value) { $value->n = 99; });
    echo "ready\n"; flush();
    $db->patch('a','b',['$inc'=>$value], requestId:str_repeat('2',32));
    check($value->n === 99);
    break;
case 'rebind':
    action($db);
    try { action($db); throw new RuntimeException('cached binding bypassed'); }
    catch (UncertainWriteException) { throw new RuntimeException('rebound seed dispatched'); }
    catch (DriverException) {}
    break;
case 'cancel':
case 'decode-cancel':
case 'read-decode-cancel':
case 'cancel-backoff':
    $token = new CancellationToken();
    pcntl_async_signals(true);
    pcntl_signal(SIGUSR1, function () use ($token) { $token->cancel(); });
    echo "ready\n"; flush();
    try { if ($case === 'read-decode-cancel') { $db->health(cancellation:$token); } else { $db->put('a','b',"n: 0\n", cancellation:$token); } throw new RuntimeException('cancellation ignored'); }
    catch (UncertainWriteException $e) { check($e->reason === CancelledException::class); }
    catch (CancelledException) { check($case !== 'decode-cancel', 'decode cancellation lost uncertainty'); }
    break;
case 'deadline':
    try { $db->health(); throw new RuntimeException('deadline ignored'); } catch (DeadlineException) {}
    break;
case 'read-decode-deadline':
    try { $db->health(); throw new RuntimeException('public decode deadline ignored'); } catch (DeadlineException) {}
    break;
case 'decode-deadline':
    try { action($db); throw new RuntimeException('decode deadline ignored'); }
    catch (UncertainWriteException $e) { check($e->reason === DeadlineException::class); }
    break;
case 'fibers':
    $fiber = new Fiber(function () use ($db) { try { action($db); throw new RuntimeException('fiber dispatch allowed'); } catch (LogicException) {} });
    $fiber->start();
    $token = new CancellationToken(); $token->cancel();
    try { $db->put('a','b',"n: 0\n", cancellation:$token); throw new RuntimeException('pre-cancel ignored'); } catch (CancelledException) {}
    action($db);
    break;
case 'rpc':
    $recoveries = [];
    while (($line = fgets(STDIN)) !== false) {
        try {
            $request = json_decode($line, true, 64, JSON_THROW_ON_ERROR);
            $result = $request['method'] === 'recoverSaved' ? $db->recover($recoveries[$request['args']['id']]) : $db->{$request['method']}(...($request['args'] ?? []));
            echo json_encode(['ok'=>$result], JSON_THROW_ON_ERROR), "\n";
        } catch (UncertainWriteException $e) {
            $recoveries[$e->requestId] = $e;
            echo json_encode(['uncertain'=>$e->requestId,'reason'=>$e->reason,'status'=>$e->status]), "\n";
        } catch (DriverException $e) { echo json_encode(['error'=>$e::class,'status'=>$e instanceof HttpException ? $e->status : null]), "\n"; }
        flush();
    }
    break;
default: throw new RuntimeException('unknown test');
}
if ($case !== 'rpc') { echo "ok\n"; }
