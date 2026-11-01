<?php
declare(strict_types=1);

// Installed at vendor/yamora/driver/examples/crud.php.
require_once dirname(__DIR__, 3) . '/autoload.php';

function requiredEnvironment(string $name): string
{
    $value = getenv($name);
    if ($value === false || $value === '') {
        throw new InvalidArgumentException('missing required example configuration');
    }
    return $value;
}

try {
    $certificate = getenv('YAMORA_CLIENT_CERT_FILE') ?: null;
    $key = getenv('YAMORA_CLIENT_KEY_FILE') ?: null;
    if (($certificate === null) !== ($key === null)) {
        throw new InvalidArgumentException('supply both client identity files');
    }
    $port = filter_var(requiredEnvironment('YAMORA_PORT'), FILTER_VALIDATE_INT,
        ['options' => ['min_range' => 1, 'max_range' => 65535]]);
    if ($port === false) {
        throw new InvalidArgumentException('invalid example port');
    }
    $client = new Yamora\Client(
        host: getenv('YAMORA_HOST') ?: '127.0.0.1', port: $port,
        readToken: requiredEnvironment('YAMORA_READ_TOKEN'),
        writeToken: requiredEnvironment('YAMORA_WRITE_TOKEN'),
        tls: new Yamora\TlsOptions(requiredEnvironment('YAMORA_CA_FILE'), $certificate, $key),
    );
    $collection = getenv('YAMORA_COLLECTION') ?: 'package-demo';
    $document = getenv('YAMORA_DOCUMENT') ?: 'php';
    $original = "# authored café\r\nname: Ada\r\nvisits: 1\r\n";
    $updated = "# edited café, still CRLF\r\nname: Ada Lovelace\r\nvisits: 2\r\n";
    $client->put($collection, $document, $original, createOnly: true);
    $read = $client->get($collection, $document);
    if ($read->source !== $original) {
        throw new RuntimeException('source changed');
    }
    $client->put($collection, $document, $updated, etag: $read->etag);
    $read = $client->get($collection, $document);
    if ($read->source !== $updated) {
        throw new RuntimeException('updated source changed');
    }
    $client->delete($collection, $document, etag: $read->etag);
    try {
        $client->get($collection, $document);
        throw new RuntimeException('deleted document still exists');
    } catch (Yamora\HttpException $error) {
        if ($error->status !== 404) {
            throw $error;
        }
    }
    echo "CRUD_OK\n";
} catch (Throwable) {
    fwrite(STDERR, "CRUD failed; reconcile any uncertain write before retrying.\n");
    exit(1);
}
