//! A disposable examples/one document; credentials and TLS files come from the caller.
use std::{
    env,
    io::{self, Write},
};
use yamora::{Client, ClientIdentity, Condition, Config, TlsOptions, WriteOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new(env::var("YAMORA_ENDPOINT")?);
    config.read_token = Some(env::var("YAMORA_READ_TOKEN")?);
    config.write_token = Some(env::var("YAMORA_WRITE_TOKEN")?);
    if env::var_os("YAMORA_CA_FILE").is_none()
        && [
            "YAMORA_CLIENT_CERT",
            "YAMORA_CLIENT_KEY",
            "YAMORA_SERVER_NAME",
        ]
        .iter()
        .any(|name| env::var_os(name).is_some())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TLS identity or server name requires a CA file",
        )
        .into());
    }
    if let Some(ca_file) = env::var_os("YAMORA_CA_FILE") {
        let identity = match (
            env::var_os("YAMORA_CLIENT_CERT"),
            env::var_os("YAMORA_CLIENT_KEY"),
        ) {
            (None, None) => None,
            (Some(certificate), Some(private_key)) => Some(ClientIdentity {
                certificate: certificate.into(),
                private_key: private_key.into(),
            }),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "client certificate and key must be supplied together",
                )
                .into());
            }
        };
        config.tls = Some(TlsOptions {
            ca_file: ca_file.into(),
            identity,
            server_name: env::var("YAMORA_SERVER_NAME").ok(),
        });
    }
    let client = Client::new(config)?;
    let authored = b"# keep this comment\r\nname: 'first'\r\nn: 1\r\n";
    client.put(
        "examples",
        "one",
        authored,
        WriteOptions {
            condition: Condition::CreateOnly,
            request_id: None,
        },
    )?;
    let document = client.get("examples", "one", None)?;
    assert_eq!(document.source, authored);
    client.patch(
        "examples",
        "one",
        br#"{"$inc":{"n":1}}"#,
        WriteOptions {
            condition: Condition::IfMatch(&document.etag),
            request_id: None,
        },
    )?;
    let result = client.query("examples", br#"{"filter":{"n":2},"limit":10}"#)?;
    io::stdout().write_all(&result.body)?;
    Ok(())
}
