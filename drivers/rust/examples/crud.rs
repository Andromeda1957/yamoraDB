//! Creates, replaces and deletes the disposable examples/package-crud document.
use std::{env, io};
use yamora::{Client, ClientIdentity, Condition, Config, TlsOptions, WriteOptions};

fn required(name: &str) -> io::Result<String> {
    env::var(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, name))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new(format!(
        "{}:{}",
        required("YAMORA_HOST")?,
        required("YAMORA_PORT")?
    ));
    config.read_token = Some(required("YAMORA_READ_TOKEN")?);
    config.write_token = Some(required("YAMORA_WRITE_TOKEN")?);
    config.tls = Some(TlsOptions {
        ca_file: required("YAMORA_CA_FILE")?.into(),
        identity: Some(ClientIdentity {
            certificate: required("YAMORA_CLIENT_CERT")?.into(),
            private_key: required("YAMORA_CLIENT_KEY")?.into(),
        }),
        server_name: None,
    });
    let client = Client::new(config)?;
    let source = "# keep café and CRLF\r\nname: '001'\r\nn: 1 # retained\r\n".as_bytes();
    let replacement = "# keep café and CRLF\r\nname: '001'\r\nn: 2 # retained\r\n".as_bytes();
    client.put(
        "examples",
        "package-crud",
        source,
        WriteOptions {
            condition: Condition::CreateOnly,
            request_id: None,
        },
    )?;
    let original = client.get("examples", "package-crud", None)?;
    assert_eq!(original.source, source);
    client.put(
        "examples",
        "package-crud",
        replacement,
        WriteOptions {
            condition: Condition::IfMatch(&original.etag),
            request_id: None,
        },
    )?;
    let updated = client.get("examples", "package-crud", None)?;
    assert_eq!(updated.source, replacement);
    client.delete(
        "examples",
        "package-crud",
        WriteOptions {
            condition: Condition::IfMatch(&updated.etag),
            request_id: None,
        },
    )?;
    println!("source-preserving CRUD passed");
    Ok(())
}
