<?php
declare(strict_types=1);

// Persistent v2 adapter. The public ClusterClient owns all routing and retries.
require_once __DIR__ . '/../src/ClusterClient.php';
use Yamora\{ClusterClient, TlsOptions, UncertainWriteException, HttpException,
    ProtocolException, TransportException, DeadlineException, CancelledException, DriverException};

final class ReplicaInput extends RuntimeException {}
final class HttpReplica
{
    private const LINE = 16384;
    private const FILE = 131072;
    private array $recoveries = [];
    private ClusterClient $client;
    private function __construct(private readonly string $root) {}
    private static function need(bool $ok): void { if (!$ok) { throw new ReplicaInput(); } }
    private static function keys(stdClass $v, array $keys): void
    {
        $actual = array_keys((array)$v); sort($actual); sort($keys); self::need($actual === $keys);
    }
    // json_decode alone accepts duplicate object keys. Scan the validated JSON
    // tokens too, including escaped key spellings, before using decoded values.
    private static function scan(string $raw, int &$at, int $depth): void
    {
        $at += strspn($raw, " \t\r\n", $at);
        $c = $raw[$at] ?? '';
        if ($c === '{' || $c === '[') {
            self::need($depth <= 12);
            ++$at; $seen = []; $end = $c === '{' ? '}' : ']';
            $at += strspn($raw, " \t\r\n", $at);
            if (($raw[$at] ?? '') === $end) { ++$at; return; }
            while (true) {
                if ($c === '{') {
                    $start = $at; self::scanString($raw, $at);
                    $key = json_decode(substr($raw, $start, $at - $start), true, 12, JSON_THROW_ON_ERROR);
                    self::need(!isset($seen[$key])); $seen[$key] = true;
                    $at += strspn($raw, " \t\r\n", $at); self::need(($raw[$at++] ?? '') === ':');
                }
                self::scan($raw, $at, $depth + 1);
                $at += strspn($raw, " \t\r\n", $at); $next = $raw[$at++] ?? '';
                if ($next === $end) { return; }
                self::need($next === ','); $at += strspn($raw, " \t\r\n", $at);
            }
        }
        if ($c === '"') { self::scanString($raw, $at); return; }
        self::need(preg_match('/\G(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/', $raw, $m, 0, $at) === 1);
        $value = json_decode($m[0], false, 12, JSON_THROW_ON_ERROR);
        self::need(!is_float($value) || is_finite($value)); $at += strlen($m[0]);
    }
    private static function scanString(string $raw, int &$at): void
    {
        self::need(($raw[$at++] ?? '') === '"');
        while ($at < strlen($raw)) {
            $c = $raw[$at++]; if ($c === '"') { return; }
            if ($c === '\\') { ++$at; }
        }
        throw new ReplicaInput();
    }
    private static function json(string $raw): stdClass
    {
        $value = json_decode($raw, false, 13, JSON_THROW_ON_ERROR);
        self::need($value instanceof stdClass);
        $at = 0; self::scan($raw, $at, 1); $at += strspn($raw, " \t\r\n", $at);
        self::need($at === strlen($raw)); return $value;
    }
    private static function noLinks(string $path, bool $directory): void
    {
        self::need(str_starts_with($path, '/') && !str_contains($path, "\0"));
        $current = '';
        foreach (explode('/', substr($path, 1)) as $part) {
            self::need($part !== '' && $part !== '.' && $part !== '..');
            $current .= '/' . $part; self::need(!is_link($current));
        }
        self::need($directory ? is_dir($path) : is_file($path));
    }
    private function read(string $relative, int $limit = self::FILE): string
    {
        $path = $this->root . '/' . $relative; self::noLinks($path, false);
        $f = fopen($path, 'rb'); self::need($f !== false);
        try { $raw = stream_get_contents($f, $limit + 1); }
        finally { fclose($f); }
        self::need(is_string($raw) && strlen($raw) <= $limit); return $raw;
    }
    private function output(int $seq, string $name, string $bytes): string
    {
        self::need(strlen($bytes) <= self::FILE);
        $dir = sprintf('call-%06d', $seq); self::noLinks($this->root . '/' . $dir, true);
        $relative = $dir . '/' . $name . '.bin';
        $f = fopen($this->root . '/' . $relative, 'xb'); self::need($f !== false);
        try { self::need(fwrite($f, $bytes) === strlen($bytes)); }
        finally { fclose($f); }
        return $relative;
    }
    public static function open(array $argv): self
    {
        self::need(count($argv) === 5 && $argv[1] === '--config' && $argv[3] === '--root');
        $self = new self($argv[4]); self::noLinks($self->root, true);
        self::need($argv[2] === $self->root . '/config.json');
        $c = self::json($self->read('config.json', self::LINE));
        self::keys($c, ['schema','cluster_id','voters','seeds','tls','tokens','timeout_ms','attempt_timeout_ms']);
        self::need($c->schema === 'yamora-http-replica-config/2' && $c->voters === 3 &&
            is_string($c->cluster_id) && preg_match('/\A[0-9a-f]{32}\z/D', $c->cluster_id) === 1 &&
            $c->cluster_id !== str_repeat('0',32) && $c->timeout_ms === 15000 && $c->attempt_timeout_ms === 3000 &&
            is_array($c->seeds) && count($c->seeds) === 3 && $c->tls instanceof stdClass && $c->tokens instanceof stdClass);
        self::keys($c->tls, ['ca_file','cert_file','key_file']); self::keys($c->tokens, ['read_file','write_file']);
        self::need($c->tls->ca_file === 'ca.pem' && $c->tls->cert_file === 'client.pem' && $c->tls->key_file === 'client.key' &&
            $c->tokens->read_file === 'read.token' && $c->tokens->write_file === 'write.token');
        $seeds = []; $ports = []; $nodes = [];
        foreach ($c->seeds as $seed) {
            self::need($seed instanceof stdClass); self::keys($seed, ['host','port','node']);
            self::need($seed->host === '127.0.0.1' && is_int($seed->port) && $seed->port >= 1 && $seed->port <= 65535 &&
                $seed->port !== 8000 && is_int($seed->node) && $seed->node >= 1 && $seed->node <= 3 &&
                !isset($ports[$seed->port]) && !isset($nodes[$seed->node]));
            $ports[$seed->port] = true; $nodes[$seed->node] = true; $seeds[] = (array)$seed;
        }
        foreach (['ca.pem','client.pem','client.key'] as $name) { self::need($self->read($name, self::LINE) !== ''); }
        $read = rtrim($self->read('read.token', 512), "\r\n"); $write = rtrim($self->read('write.token', 512), "\r\n");
        self::need(preg_match('/\A[!-~]{32,512}\z/D', $read) === 1 && preg_match('/\A[!-~]{32,512}\z/D', $write) === 1);
        $self->client = new ClusterClient($seeds, $c->cluster_id, 3,
            new TlsOptions($self->root . '/ca.pem', $self->root . '/client.pem', $self->root . '/client.key'),
            $read, $write, 15, 3, self::FILE);
        return $self;
    }
    private static function category(Throwable $error): ?string
    {
        return match ($error::class) {
            HttpException::class => 'status', DeadlineException::class => 'deadline',
            CancelledException::class => 'cancelled', ProtocolException::class => 'protocol',
            TransportException::class => 'transport', default => null,
        };
    }
    private static function blank(int $seq, string $action): array
    {
        return ['schema'=>'yamora-http-replica-observation/2', 'seq'=>$seq, 'action'=>$action,
            'outcome'=>'success', 'error_kind'=>null, 'elapsed_ns'=>0,
            'api'=>['status'=>null,'body_file'=>null,'etag'=>null,'revision'=>null,'receipt'=>null],
            'sdk_request_id'=>null,'envelope'=>null,'recovery_mode'=>null,'recovery_handle'=>null];
    }
    private function command(stdClass $c, int $seq): array
    {
        self::need(($c->schema ?? null) === 'yamora-http-replica-command/2' && ($c->seq ?? null) === $seq);
        $action = $c->action ?? null; self::need(in_array($action, ['call','recover','close'], true));
        $o = self::blank($seq, $action);
        if ($action === 'close') { self::keys($c, ['schema','seq','action']); $this->recoveries = []; unset($this->client); $o['outcome']='closed'; return $o; }
        if ($action === 'recover') {
            self::keys($c, ['schema','seq','action','handle']);
            self::need(is_string($c->handle) && isset($this->recoveries[$c->handle]));
            $failure = $this->recoveries[$c->handle]; $o['recovery_handle']=$c->handle; $o['recovery_mode']='sdk-envelope';
        } else {
            self::keys($c, ['schema','seq','action','method','collection','document','source_file','request_id','if_match','if_none_match']);
            self::need(in_array($c->method, ['GET','PUT','PATCH','DELETE'], true));
            foreach ([$c->collection,$c->document] as $id) { self::need(is_string($id) && preg_match('/\A[a-z0-9-]{1,128}\z/D', $id) === 1); }
            self::need($c->method === 'GET' || $c->collection !== 'yamldb-system');
            self::need($c->request_id === null || (is_string($c->request_id) && preg_match('/\A[0-9a-f]{32}\z/D', $c->request_id) === 1 && $c->request_id !== str_repeat('0',32)));
            self::need($c->if_match === null || (is_string($c->if_match) && preg_match('/\A"[0-9a-f]{16}"\z/D', $c->if_match) === 1));
            self::need($c->if_none_match === null || ($c->if_none_match === '*' && $c->method === 'PUT' && $c->if_match === null));
            self::need($c->method !== 'GET' || ($c->request_id === null && $c->if_match === null && $c->if_none_match === null));
            $args = [$c->collection,$c->document];
            if (in_array($c->method, ['PUT','PATCH'], true)) {
                self::need(is_string($c->source_file) && preg_match('~\Ainput/[a-z0-9-]{1,64}\.bin\z~D', $c->source_file) === 1);
                $bytes = $this->read($c->source_file); self::need($bytes !== '');
                if ($c->method === 'PATCH') {
                    $patch = self::json($bytes); self::keys($patch, ['$inc']);
                    self::need($patch->{'$inc'} instanceof stdClass); self::keys($patch->{'$inc'}, ['n']);
                    self::need($patch->{'$inc'}->n === 1); $args[] = $patch;
                } else { self::need(preg_match('//u', $bytes) === 1); $args[] = $bytes; }
            } else { self::need($c->source_file === null); }
            if ($c->method !== 'GET') {
                $args['etag'] = $c->if_match === null ? null : substr($c->if_match,1,-1);
                $args['requestId'] = $c->request_id;
                if ($c->method === 'PUT') { $args['createOnly'] = $c->if_none_match === '*'; }
                // Reserve capacity before any potentially uncertain dispatch.
                self::need(count($this->recoveries) < 16);
            }
        }
        $started = hrtime(true);
        try {
            if ($action === 'recover') { $result = $this->client->recover($failure); }
            elseif ($c->method === 'GET') { $result = $this->client->get(...$args); }
            else { $prepared = $this->client->prepareMutation(strtolower($c->method), $args); $result = $this->client->execute($prepared); }
            $o['elapsed_ns'] = hrtime(true) - $started;
            if ($result instanceof Yamora\Document) {
                $o['api']['body_file'] = $this->output($seq, 'body', $result->source);
                $o['api']['etag']=$result->etag; $o['api']['revision']=$result->revision;
            } elseif (is_string($result)) { $o['api']['revision']=$result; }
            else {
                $receipt = [];
                foreach (['status','collection','document','etag','revision'] as $key) { $receipt[$key]=$result->$key; }
                $o['api']['receipt']=$receipt; $o['api']['etag']=$result->etag; $o['api']['revision']=$result->revision;
            }
        } catch (UncertainWriteException $e) {
            $o['elapsed_ns'] = hrtime(true) - $started; $o['outcome']='uncertain';
            $o['error_kind'] = match ($e->reason) {
                HttpException::class=>'status', DeadlineException::class=>'deadline', CancelledException::class=>'cancelled',
                ProtocolException::class=>'protocol', TransportException::class=>'transport', default=>null,
            };
            $o['api']['status']=$e->status; $o['sdk_request_id']=$e->requestId;
            if ($action === 'call') { $o['recovery_handle']='h'.(count($this->recoveries)+1); $this->recoveries[$o['recovery_handle']]=$e; }
            $o['recovery_mode']='sdk-envelope'; $p=$e->mutation;
            $o['envelope']=['method'=>$p->method,'path'=>$p->path,'if_match'=>$p->headers['If-Match'] ?? null,
                'if_none_match'=>$p->headers['If-None-Match'] ?? null,'request_id'=>$p->requestId,
                'body_file'=>$this->output($seq, 'envelope', $p->body)];
        } catch (DriverException $e) {
            $o['elapsed_ns'] = hrtime(true) - $started; $kind=self::category($e); self::need($kind !== null);
            $o['outcome']=$kind; $o['error_kind']=$kind; $o['api']['status']=$e instanceof HttpException ? $e->status : null;
        }
        return $o;
    }
    public function run(): int
    {
        for ($seq=1; $seq<=64; ++$seq) {
            $line = fgets(STDIN, self::LINE + 1);
            self::need(is_string($line) && str_ends_with($line, "\n") && !str_contains($line, "\r") && strlen($line) <= self::LINE);
            $o = $this->command(self::json($line), $seq);
            $encoded = json_encode($o, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
            self::need(strlen($encoded) <= self::LINE); self::need(fwrite(STDOUT, $encoded) === strlen($encoded)); fflush(STDOUT);
            if ($o['outcome'] === 'closed') { return 0; }
        }
        throw new ReplicaInput();
    }
}
// Never print exceptions, paths, source bytes, peer messages or credentials.
ini_set('display_errors', '0'); ini_set('log_errors', '0');
set_error_handler(static function (int $severity): bool {
    // The public SDK suppresses socket/TLS warnings and classifies the result.
    // Unsuppressed adapter/file warnings still fail closed with fixed diagnostics.
    if (($severity & error_reporting()) === 0) { return true; }
    throw new ReplicaInput();
});
try { exit(HttpReplica::open($argv)->run()); }
catch (Throwable) { fwrite(STDERR, "http replica adapter: invalid input or infrastructure failure\n"); exit(2); }
