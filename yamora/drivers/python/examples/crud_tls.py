"""Run public HTTP CRUD against an explicitly trusted private Yamora endpoint."""

import argparse
import ssl
from pathlib import Path

from yamora import YamoraClient
from yamora import YamoraClientError

SOURCE = '# packaged client\r\nname: "café"\r\nvalue: 01\r\n'.encode()
UPDATED = SOURCE.replace(b"value: 01", b"value: 02")


def run(args):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=args.ca)
    if bool(args.cert) != bool(args.key):
        raise ValueError("client certificate and key must be supplied together")
    if args.cert:
        context.load_cert_chain(args.cert, args.key)
    client = YamoraClient(
        host=args.host,
        port=args.port,
        timeout=10,
        tls_context=context,
        auth_token_file=args.read_token_file,
        write_auth_token_file=args.write_token_file,
    )
    stored = client.put(args.collection, args.document, SOURCE, create_only=True)
    found = client.get(args.collection, args.document)
    if found != SOURCE:
        raise RuntimeError("exact source check failed")
    updated = client.put(args.collection, args.document, UPDATED, etag=stored["etag"])
    try:
        client.put(args.collection, args.document, SOURCE, etag=stored["etag"])
    except YamoraClientError as error:
        if error.status != 412:
            raise
    else:
        raise RuntimeError("stale precondition was accepted")
    if client.get(args.collection, args.document) != UPDATED:
        raise RuntimeError("guarded update check failed")
    client.delete(args.collection, args.document, etag=updated["etag"])
    try:
        client.get(args.collection, args.document)
    except YamoraClientError as error:
        if error.status != 404:
            raise
    else:
        raise RuntimeError("deleted document remains visible")
    print("YAMORA_PYTHON_PACKAGE_CRUD_OK")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--read-token-file", type=Path, required=True)
    parser.add_argument("--write-token-file", type=Path, required=True)
    parser.add_argument("--collection", default="packaged")
    parser.add_argument("--document", default="python-example")
    args = parser.parse_args()
    try:
        run(args)
    except (OSError, ValueError, YamoraClientError, RuntimeError):
        parser.exit(1, "packaged CRUD failed; preserve uncertain writes for explicit recovery\n")


if __name__ == "__main__":
    main()
