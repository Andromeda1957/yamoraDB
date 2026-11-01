<?php
declare(strict_types=1);
require_once (getenv('BINARY_SOURCE') ?: __DIR__ . '/../src') . '/BinaryClient.php';
require_once (getenv('BINARY_SOURCE') ?: __DIR__ . '/../src') . '/BinaryOperationClient.php';

function verifyOperation(bool $condition, string $message): void
{
    if (!$condition) { throw new RuntimeException($message); }
}
function operationMetadata(int $status, int $length, int $mode): string
{
    $fields = [1 => pack('n', $status), 2 => $mode ? 'application/x-ndjson' : 'application/json',
        3 => pack('NN', 0, $length), 4 => pack('NN', 0, $length),
        5 => '0123456789abcdef', 13 => chr($mode)];
    $bytes = pack('nn', 2, count($fields));
    foreach ($fields as $id => $value) { $bytes .= pack('nn', $id, strlen($value)) . $value; }
    return $bytes;
}
$case = $argv[1] ?? 'finite-query';
if (in_array($case, ['finite-query', 'patch-receipt', 'feed-mode'], true)) {
    $bytes = operationMetadata(200, $case === 'feed-mode' ? 0 : 25, $case === 'feed-mode' ? 1 : 0);
    $accepted = false;
    try {
        $fields = Yamora\BinaryCodec::fields($bytes, 2);
        $accepted = ($fields[13] ?? null) === ($case === 'feed-mode' ? "\1" : "\0");
    } catch (Yamora\ProtocolException) {}
    verifyOperation($accepted, 'SCHEMA2_' . strtoupper(str_replace('-', '_', $case)) . '_ACCEPTED');
    echo "ok\n";
    exit(0);
}
if ($case === 'semantics') {
    $control = new Yamora\OperationControl(hrtime(true) / 1e9 + 10);
    $raw = '{"revision":"0123456789abcdef","documents":[9007199254740993,1.2300,1e999999]}';
    $v = Yamora\BinaryRawJson::object($raw, $control);
    verifyOperation($v->documents[0]->lexeme === '9007199254740993' && $v->documents[1]->lexeme === '1.2300' &&
        $v->documents[2]->lexeme === '1e999999', 'LOSSLESS_RAW_NUMBERS');
    foreach (['{"x":1,"\u0078":2}', '{"x":01}', '{"x":[}', '{"x":1e}', '{"x":"\ud800"}'] as $bad) {
        $failed = false;
        try { Yamora\BinaryRawJson::object($bad, $control); } catch (Yamora\ProtocolException) { $failed = true; }
        verifyOperation($failed, 'STRICT_RAW_JSON');
    }
    $e = new Yamora\BinaryOperationEnvelope('POST', '/v1/query/a', $raw, 'Application/JSON', '', null, str_repeat('07', 16));
    verifyOperation(!$e->isMutation() && $e->source === $raw && $e->ifMatch === '', 'IMMUTABLE_READ_ENVELOPE');
    verifyOperation((new Yamora\BinaryOperationEnvelope('POST', '/v1/transactions', '{}', 'application/json'))->isMutation(), 'TRANSACTION_MUTATION');
    $token = 'v1.' . str_repeat('a', 32) . '.0000000000000005';
    $page = json_encode(['transactions' => [], 'next_after' => $token, 'oldest_after' => $token,
        'checkpoint' => $token, 'revision' => '0123456789abcdef', 'has_more' => false], JSON_THROW_ON_ERROR) . "\n";
    verifyOperation(Yamora\BinaryOperationCodec::page($page, $token, $control)->bytes === $page, 'EXACT_PAGE_BYTES');
    foreach ([substr($page, 0, -1), str_replace('"has_more":false', '"has_more":false,"has_\\u006dore":false', $page),
        str_replace($token, 'v1.' . str_repeat('b', 32) . '.0000000000000005', $page)] as $bad) {
        $failed = false;
        try { Yamora\BinaryOperationCodec::page($bad, $token, $control); } catch (Yamora\ProtocolException) { $failed = true; }
        verifyOperation($failed, 'PAGE_VALIDATION_BEFORE_EXPOSURE');
    }
    echo "ok\n"; exit(0);
}
if ($case === 'call') {
    $s = json_decode(getenv('BINARY_CONFIG'), true, 16, JSON_THROW_ON_ERROR);
    $command = json_decode(stream_get_contents(STDIN), true, 32, JSON_THROW_ON_ERROR);
    $client = new Yamora\BinaryOperationClient(new Yamora\BinaryConfig('127.0.0.1', $s['port'], '127.0.0.1',
        file_get_contents($s['ca']), getenv('TMPDIR'), file_get_contents($s['cert']), file_get_contents($s['key']), $s['timeout'] ?? 2, 4096));
    $cancel = new Yamora\CancellationToken(); if ($command['pre'] ?? false) { $cancel->cancel(); }
    $pages = []; $result = [];
    try {
        $args = ['token' => $command['token'] ?? str_repeat('r', 32), 'requestId' => str_repeat('07', 16), 'cancellation' => $cancel,
            'ifMatch' => $command['ifMatch'] ?? null, 'ifNoneMatch' => $command['ifNoneMatch'] ?? null];
        if ($command['feed'] ?? false) {
            $r = $client->feed($command['target'], static function (Yamora\BinaryChangePage $p) use (&$pages, $command): bool {
                $pages[] = base64_encode($p->bytes); return !($command['callbackCancel'] ?? false);
            }, ...$args);
            $result = ['metadata' => $r->metadata, 'lastAfter' => $r->lastAfter, 'terminal' => $r->terminalStatus];
        } else {
            $r = $client->operation($command['method'], $command['target'], base64_decode($command['source'] ?? '', true), $command['contentType'] ?? '', ...$args);
            $result = ['metadata' => $r->metadata, 'body' => base64_encode($r->body)];
        }
    } catch (Yamora\BinaryOperationException $e) {
        $result = ['error' => $e->reason, 'metadata' => $e->metadata, 'lastAfter' => $e->lastAfter, 'status' => $e->status];
        if ($e instanceof Yamora\BinaryOperationUncertainException) {
            $original = $e->envelope;
            $result['envelope'] = ['method' => $original->method, 'target' => $original->target, 'contentType' => $original->contentType,
                'source' => base64_encode($original->source), 'ifMatch' => $original->ifMatch, 'ifNoneMatch' => $original->ifNoneMatch, 'id' => $original->requestId];
        }
    } finally { $client->close(); }
    echo json_encode($result + ['pages' => $pages], JSON_THROW_ON_ERROR), "\n"; exit(0);
}
throw new RuntimeException('unknown operation check');
