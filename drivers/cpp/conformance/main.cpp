// Observations from the public SDK only; no protocol or scenario assertions.
#include <yamora/binary.hpp>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <set>
#include <thread>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

namespace {
using Args = std::map<std::string, std::string>;
const std::set<std::string> required = {"host", "port", "server-name", "ca-file", "cert-file", "key-file",
    "method", "collection", "document", "source-file", "request-id", "timeout-ms",
    "max-frame-bytes", "cancel-mode", "output-dir"};
void check(bool ok) { if (!ok) throw std::runtime_error("adapter input or infrastructure"); }
Args arguments(int argc, char **argv) {
    Args args;
    check(argc == 31 || argc == 33 || argc == 35 || argc == 37);
    for (int i = 1; i < argc; i += 2) {
        std::string flag = argv[i];
        check(flag.rfind("--", 0) == 0 && i + 1 < argc);
        auto key = flag.substr(2);
        check(required.count(key) || key == "token-file" || key == "if-match" || key == "if-none-match");
        std::string value = argv[i + 1];
        check(value.size() <= 4096 && args.emplace(key, value).second);
    }
    for (const auto &key : required) check(args.count(key) == 1);
    return args;
}
int number(const std::string &value, int maximum) {
    check(!value.empty() && value.size() <= 5);
    int result = 0;
    for (char ch : value) { check(ch >= '0' && ch <= '9'); result = result * 10 + ch - '0'; }
    check(result > 0 && result <= maximum);
    return result;
}
std::string read(const std::string &path, std::size_t cap) {
    check(std::filesystem::path(path).is_absolute());
    std::ifstream file(path, std::ios::binary);
    check(file.is_open());
    std::string value(cap + 1, '\0');
    file.read(value.data(), static_cast<std::streamsize>(value.size()));
    check(!file.bad());
    value.resize(static_cast<std::size_t>(file.gcount()));
    check(value.size() <= cap);
    return value;
}
void write(const std::filesystem::path &root, const char *name, const std::string &bytes) {
    int fd = ::open((root / name).c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    check(fd >= 0);
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        auto n = ::write(fd, bytes.data() + offset, bytes.size() - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ::close(fd); check(false); }
        offset += static_cast<std::size_t>(n);
    }
    check(::close(fd) == 0);
}
std::string quote(std::string_view value) {
    const char *hex = "0123456789abcdef";
    std::string out = "\"";
    for (char raw : value) {
        auto ch = static_cast<unsigned char>(raw);
        if (ch == '"' || ch == '\\') { out += '\\'; out += static_cast<char>(ch); }
        else if (ch < 32) { out += "\\u00"; out += hex[ch >> 4]; out += hex[ch & 15]; }
        else out += static_cast<char>(ch);
    }
    return out + '"';
}
std::string optional(const std::optional<std::string> &value) { return value ? quote(*value) : "null"; }
std::optional<std::string> option(const Args &args, const char *key) {
    auto found = args.find(key); return found == args.end() ? std::nullopt : std::optional<std::string>(found->second);
}
const char *method_name(yamora::BinaryMethod method) {
    switch (method) {
        case yamora::BinaryMethod::get: return "GET";
        case yamora::BinaryMethod::head: return "HEAD";
        case yamora::BinaryMethod::put: return "PUT";
        case yamora::BinaryMethod::erase: return "DELETE";
    }
    throw std::runtime_error("method");
}
const char *kind(yamora::ErrorKind kind) {
    switch (kind) {
        case yamora::ErrorKind::http: return "status";
        case yamora::ErrorKind::schema_policy_replication_unsupported: return "status";
        case yamora::ErrorKind::deadline: return "deadline";
        case yamora::ErrorKind::cancelled: return "cancelled";
        case yamora::ErrorKind::protocol: return "protocol";
        case yamora::ErrorKind::transport: return "transport";
        default: throw std::runtime_error("unexpected SDK error kind");
    }
}
// Sole reader of the runner-owned stdin pipe; every wait is capped at 20 ms.
class Control {
    std::atomic<bool> stop_{false}, good_{true};
    std::thread thread_;
public:
    Control(bool enabled, std::shared_ptr<yamora::Cancellation> token) {
        if (!enabled) return;
        std::promise<void> ready;
        auto started = ready.get_future();
        thread_ = std::thread([this, token, ready = std::move(ready)]() mutable {
            ready.set_value();
            int state = 0;
            while (!stop_.load()) {
                pollfd fd{STDIN_FILENO, POLLIN, 0};
                auto result = ::poll(&fd, 1, 20);
                if (result < 0 && errno == EINTR) continue;
                if (result < 0 || (fd.revents & (POLLERR | POLLNVAL))) { good_ = false; token->cancel(); return; }
                if (!result) continue;
                char bytes[3]{};
                auto n = ::read(STDIN_FILENO, bytes, sizeof(bytes));
                if (n < 0 && errno == EINTR) continue;
                if (n == 0 && state != 1) return;
                if (n <= 0) { good_ = false; token->cancel(); return; }
                for (ssize_t i = 0; i < n; ++i) {
                    if (state == 2 || bytes[i] != (state == 1 ? '\n' : 'C')) { good_ = false; token->cancel(); return; }
                    ++state;
                }
                if (state == 2) token->cancel();
            }
            if (state == 1) { good_ = false; token->cancel(); }
        });
        started.wait();
    }
    void finish() { stop_ = true; if (thread_.joinable()) thread_.join(); check(good_); }
    ~Control() { stop_ = true; if (thread_.joinable()) thread_.join(); }
};

std::string run(int argc, char **argv) {
    const auto args = arguments(argc, argv);
    auto get = [&args](const char *key) -> const std::string & { return args.at(key); };
    const auto port = number(get("port"), 65535), timeout = number(get("timeout-ms"), 30000);
    check(get("host") == "127.0.0.1" && get("server-name") == "localhost" && port != 8000 && get("max-frame-bytes") == "4096");
    check(get("cancel-mode") == "none" || get("cancel-mode") == "pre" || get("cancel-mode") == "external");
    std::filesystem::path root(get("output-dir"));
    check(root.is_absolute() && std::filesystem::canonical(root) == root && std::filesystem::is_directory(root));
    auto source = read(get("source-file"), yamora::max_document_bytes);
    check(get("method") == "PUT" || source.empty());
    check(get("method") == "GET" || get("method") == "HEAD" || get("method") == "PUT" || get("method") == "DELETE");
    auto token_file = option(args, "token-file");
    auto bearer = token_file ? read(*token_file, 512) : std::string();
    yamora::BinaryConfig config;
    config.host = get("host"); config.port = port; config.server_identity = get("server-name");
    config.ca_pem = read(get("ca-file"), 65536); config.client_certificate_pem = read(get("cert-file"), 65536);
    config.client_private_key_pem = read(get("key-file"), 65536);
    config.timeout = std::chrono::milliseconds(timeout); config.max_frame_bytes = 4096; config.max_concurrent_calls = 1;
    yamora::BinaryClient client(config);
    yamora::BinaryOptions options;
    options.if_match = option(args, "if-match"); options.if_none_match = option(args, "if-none-match"); options.request_id = get("request-id");
    auto token = std::make_shared<yamora::Cancellation>();
    if (get("cancel-mode") == "pre") token->cancel();
    yamora::RequestOptions request; request.cancellation = token;
    Control control(get("cancel-mode") == "external", token);
    std::optional<yamora::BinaryResponse> response;
    std::optional<yamora::BinaryEnvelope> envelope;
    std::string outcome = "success", error_kind = "null";
    int status = 0;
    std::chrono::nanoseconds elapsed{0};
    const auto start = std::chrono::steady_clock::now();
    try {
        // Exactly one branch invokes one public operation; there is no recovery.
        response = get("method") == "GET" ? client.get(get("collection"), get("document"), bearer, options, request) :
            get("method") == "HEAD" ? client.head(get("collection"), get("document"), bearer, options, request) :
            get("method") == "PUT" ? client.put(get("collection"), get("document"), source, bearer, options, request) :
            client.erase(get("collection"), get("document"), bearer, options, request);
        elapsed = std::chrono::steady_clock::now() - start;
    } catch (const yamora::BinaryUncertainWriteError &error) {
        elapsed = std::chrono::steady_clock::now() - start;
        check(error.uncertain()); envelope = error.envelope();
        outcome = "uncertain"; error_kind = quote(kind(error.kind())); status = error.status();
    } catch (const yamora::Error &error) {
        elapsed = std::chrono::steady_clock::now() - start;
        check(!error.uncertain()); outcome = kind(error.kind()); error_kind = quote(outcome); status = error.status();
    }
    control.finish();
    std::string api = "{\"status\":" + (status ? std::to_string(status) : "null") +
        ",\"body_file\":null,\"etag\":null,\"revision\":null,\"representation_length\":null,\"request_id\":null,\"receipt\":null}";
    if (response) {
        write(root, "body.bin", response->body);
        api = "{\"status\":" + std::to_string(response->status) + ",\"body_file\":\"body.bin\",\"etag\":" +
            (response->etag.empty() ? "null" : quote(response->etag)) + ",\"revision\":" + quote(response->revision) +
            ",\"representation_length\":" + std::to_string(response->representation_length) + ",\"request_id\":" + optional(response->request_id) + ",\"receipt\":null}";
    }
    std::string original = "null";
    if (envelope) {
        write(root, "envelope.bin", envelope->source());
        const auto options = envelope->options();
        original = "{\"method\":" + quote(method_name(envelope->method())) + ",\"collection\":" + quote(envelope->collection()) +
            ",\"document\":" + quote(envelope->document()) + ",\"if_match\":" + optional(options.if_match) + ",\"if_none_match\":" + optional(options.if_none_match) +
            ",\"request_id\":" + optional(options.request_id) + ",\"source_file\":\"envelope.bin\"}";
    }
    auto json = "{\"schema\":\"yamora-observation/1\",\"outcome\":" + quote(outcome) + ",\"error_kind\":" + error_kind +
        ",\"elapsed_ns\":" + std::to_string(elapsed.count()) + ",\"api\":" + api + ",\"envelope\":" + original + "}";
    check(json.size() + 1 <= 16384);
    return json;
}
} // namespace
int main(int argc, char **argv) {
    try { std::cout << run(argc, argv) << '\n'; return std::cout ? 0 : 2; }
    catch (...) { std::cerr << "C++ conformance adapter failed\n"; return 2; }
}
