// Creates, replaces and deletes the disposable examples/package-crud document.
#include <yamora/client.hpp>
#include <yamora/binary.hpp>

#include <cstdlib>
#include <iostream>
#include <stdexcept>

namespace {
std::string required(const char* name) {
    const char* value = std::getenv(name);
    if (!value || !*value) throw std::runtime_error("required example setting is absent");
    return value;
}
void check(bool value) {
    if (!value) throw std::runtime_error("source preservation check failed");
}
}

int main() {
    try {
        yamora::Config config;
        config.host = required("YAMORA_HOST");
        auto port = required("YAMORA_PORT");
        std::size_t consumed = 0;
        config.port = std::stoi(port, &consumed);
        check(consumed == port.size());
        config.read_token = required("YAMORA_READ_TOKEN");
        config.write_token = required("YAMORA_WRITE_TOKEN");
        auto tls = std::make_shared<yamora::TLS>();
        tls->ca_file = required("YAMORA_CA_FILE");
        tls->certificate_file = required("YAMORA_CLIENT_CERT");
        tls->private_key_file = required("YAMORA_CLIENT_KEY");
        config.tls = tls;
        yamora::Client client(config);
        const std::string source = "# keep café and CRLF\r\nname: '001'\r\nn: 1 # retained\r\n";
        const std::string replacement = "# keep café and CRLF\r\nname: '001'\r\nn: 2 # retained\r\n";
        yamora::WriteOptions create;
        create.create_only = true;
        client.put("examples", "package-crud", source, create);
        auto original = client.get("examples", "package-crud");
        check(original.source == source);
        yamora::WriteOptions replace;
        replace.etag = original.etag;
        client.put("examples", "package-crud", replacement, replace);
        auto updated = client.get("examples", "package-crud");
        check(updated.source == replacement);
        yamora::WriteOptions remove;
        remove.etag = updated.etag;
        client.erase("examples", "package-crud", remove);
        std::cout << "source-preserving CRUD passed\n";
        return 0;
    } catch (const std::exception&) {
        // Avoid reflecting caller credentials or native response bodies.
        std::cerr << "CRUD failed; reconcile any uncertain mutation before repetition\n";
        return 1;
    }
}
