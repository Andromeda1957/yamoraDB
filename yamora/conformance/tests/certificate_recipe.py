"""Pure system OpenSSL recipe shared by binary conformance and SDK tests."""

import subprocess


def certs(root):
    """Only system OpenSSL, immutable caller-owned test certificates."""

    def openssl(*args):
        result = subprocess.run(["openssl", *map(str, args)], capture_output=True, timeout=15)
        if result.returncode:
            raise AssertionError(f"certificate setup failed: {result.stderr!r}")

    for ca in ("ca", "foreign"):
        openssl(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-noenc",
            "-keyout",
            root / f"{ca}.key",
            "-out",
            root / f"{ca}.pem",
            "-days",
            "1",
            "-subj",
            f"/CN={ca}",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )
    for serial, (name, ca, usage) in enumerate(
        (
            ("server", "ca", "serverAuth"),
            ("client", "ca", "clientAuth"),
            ("bad-client", "foreign", "clientAuth"),
        ),
        1,
    ):
        openssl(
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-noenc",
            "-keyout",
            root / f"{name}.key",
            "-out",
            root / f"{name}.csr",
            "-subj",
            f"/CN={name}",
        )
        ext = root / f"{name}.ext"
        ext.write_text(
            f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={usage}\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
        )
        openssl(
            "x509",
            "-req",
            "-in",
            root / f"{name}.csr",
            "-CA",
            root / f"{ca}.pem",
            "-CAkey",
            root / f"{ca}.key",
            "-set_serial",
            str(serial),
            "-out",
            root / f"{name}.pem",
            "-days",
            "1",
            "-extfile",
            ext,
        )
