#include "yamora/client.hpp"
#include "control.hpp"
#include "json.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace yamora {
Error::Error(ErrorKind kind, const char *message, int status, bool uncertain)
    : std::runtime_error(message), kind_(kind), status_(status), uncertain_(uncertain) {}
namespace {
[[noreturn]] void invalid(const char *message) {
    throw Error(ErrorKind::invalid_argument, message);
}
[[noreturn]] void protocol(const char *message) { throw Error(ErrorKind::protocol, message); }
[[noreturn]] void transport() {
    throw Error(ErrorKind::transport, "yamora: connection, TLS or deadline failure");
}
bool hex(std::string_view value, std::size_t size) {
    return value.size() == size && std::all_of(value.begin(), value.end(), [](unsigned char b) {
               return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f');
           });
}
void revision_option(std::string_view value) {
    if (!value.empty() && !hex(value, 16))
        invalid("yamora: invalid revision or ETag");
}
void identifier(std::string_view value) {
    if (value.empty() || value.size() > 128 ||
        !std::all_of(value.begin(), value.end(), [](unsigned char b) {
            return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-';
        }))
        invalid("yamora: invalid identifier");
}
void request_id(std::string_view value) {
    if (!value.empty() &&
        (!hex(value, 32) || value.find_first_not_of('0') == std::string_view::npos))
        invalid("yamora: invalid request identity");
}
bool utf8(std::string_view value, const detail::Control *control = nullptr) {
    std::size_t i = 0, next_check = 0;
    while (i < value.size()) {
        if (control && i >= next_check) {
            control->check();
            next_check = i + 1024;
        }
        auto b = static_cast<unsigned char>(value[i++]);
        if (b < 0x80) {
            if (b == 0 || (b < 32 && b != '\t' && b != '\n' && b != '\r'))
                return false;
            continue;
        }
        unsigned n;
        std::uint32_t point;
        if (b >= 0xc2 && b <= 0xdf) {
            n = 1;
            point = b & 31U;
        } else if (b >= 0xe0 && b <= 0xef) {
            n = 2;
            point = b & 15U;
        } else if (b >= 0xf0 && b <= 0xf4) {
            n = 3;
            point = b & 7U;
        } else
            return false;
        if (n > value.size() - i)
            return false;
        for (unsigned j = 0; j < n; ++j) {
            auto c = static_cast<unsigned char>(value[i++]);
            if ((c & 0xc0U) != 0x80U)
                return false;
            point = (point << 6U) | (c & 63U);
        }
        if ((n == 1 && point < 0x80) || (n == 2 && point < 0x800) || (n == 3 && point < 0x10000) ||
            (point >= 0xd800 && point <= 0xdfff) || point > 0x10ffff)
            return false;
    }
    return true;
}
void json_input(std::string_view value, std::size_t maximum) {
    if (value.empty() || value.size() > maximum || !utf8(value))
        invalid("yamora: invalid structured body size or UTF-8");
    // LibYAML interprets a literal NEL even inside JSON strings as a line break.
    if (value.find("\xc2\x85") != std::string_view::npos)
        invalid("yamora: JSON NEL must be escaped as \\u0085");
}
std::string document_path(std::string_view collection, std::string_view document) {
    identifier(collection);
    identifier(document);
    return "/v1/collections/" + std::string(collection) + "/documents/" + std::string(document);
}
std::string conditions(const WriteOptions &options, bool put) {
    revision_option(options.etag);
    request_id(options.request_id);
    if (options.create_only && (!put || !options.etag.empty()))
        invalid("yamora: conflicting or invalid preconditions");
    std::string headers;
    if (options.create_only)
        headers += "If-None-Match: *\r\n";
    if (!options.etag.empty())
        headers += "If-Match: \"" + options.etag + "\"\r\n";
    if (!options.request_id.empty())
        headers += "X-Yamora-Request-Id: " + options.request_id + "\r\n";
    return headers;
}
std::string lower(std::string value) {
    for (auto &c : value)
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char>(c + ('a' - 'A'));
    return value;
}
std::string_view trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
        value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
        value.remove_suffix(1);
    return value;
}
std::size_t length_value(std::string_view value) {
    if (value.empty())
        protocol("yamora: missing response length");
    std::size_t result = 0;
    for (char c : value) {
        if (c < '0' || c > '9' ||
            result >
                (std::numeric_limits<std::size_t>::max() - static_cast<unsigned>(c - '0')) / 10)
            protocol("yamora: invalid response length");
        result = result * 10 + static_cast<unsigned>(c - '0');
    }
    return result;
}
using Context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using Secure = std::unique_ptr<SSL, decltype(&SSL_free)>;
struct Socket {
    int fd = -1;
    ~Socket() {
        if (fd >= 0)
            ::close(fd);
    }
};
// OpenSSL's default socket BIO can raise SIGPIPE. This BIO uses MSG_NOSIGNAL
// without changing the application's global or per-thread signal policy.
const BIO_METHOD *socket_method() {
    static const std::unique_ptr<BIO_METHOD, decltype(&BIO_meth_free)> method(
        [] {
            BIO_METHOD *m =
                BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "yamora socket");
            if (!m)
                transport();
            bool ok =
                BIO_meth_set_create(m,
                                    [](BIO *b) {
                                        BIO_set_init(b, 1);
                                        return 1;
                                    }) == 1 &&
                BIO_meth_set_destroy(m, [](BIO *) { return 1; }) == 1 &&
                BIO_meth_set_write(
                    m,
                    [](BIO *b, const char *data, int count) {
                        BIO_clear_retry_flags(b);
                        auto n = ::send(*static_cast<int *>(BIO_get_data(b)), data,
                                        static_cast<std::size_t>(count), MSG_NOSIGNAL);
                        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
                            BIO_set_retry_write(b);
                        return static_cast<int>(n);
                    }) == 1 &&
                BIO_meth_set_read(
                    m,
                    [](BIO *b, char *data, int count) {
                        BIO_clear_retry_flags(b);
                        auto n = ::recv(*static_cast<int *>(BIO_get_data(b)), data,
                                        static_cast<std::size_t>(count), 0);
                        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
                            BIO_set_retry_read(b);
                        return static_cast<int>(n);
                    }) == 1 &&
                BIO_meth_set_ctrl(m, [](BIO *, int command, long, void *) -> long {
                    return command == BIO_CTRL_FLUSH ? 1L : 0L;
                }) == 1;
            if (!ok) {
                BIO_meth_free(m);
                transport();
            }
            return m;
        }(),
        BIO_meth_free);
    return method.get();
}
struct Connection {
    Socket socket;
    Secure ssl{nullptr, SSL_free}; // destroyed before socket
    detail::Control control;
    explicit Connection(detail::Control input) : control(std::move(input)) {}
    void check_time() const { control.check(); }
    void wait(short events) const {
        for (;;) {
            check_time();
            auto remaining = std::chrono::ceil<std::chrono::milliseconds>(
                                 control.deadline - std::chrono::steady_clock::now())
                                 .count();
            pollfd p{socket.fd, events, 0};
            auto result =
                ::poll(&p, 1, static_cast<int>(std::clamp<std::int64_t>(remaining, 1, 10)));
            if (result > 0) {
                if ((p.revents & POLLNVAL) != 0)
                    transport();
                return; // recv/connect/SSL will report HUP or ERR precisely
            }
            if (result == 0 || (result < 0 && errno == EINTR))
                continue;
            transport();
        }
    }
    void ssl_wait(int error) const {
        if (error == SSL_ERROR_WANT_READ)
            wait(POLLIN);
        else if (error == SSL_ERROR_WANT_WRITE)
            wait(POLLOUT);
        else
            transport();
    }
    void connect(const sockaddr_in &address, SSL_CTX *context, const std::string &host) {
        socket.fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (socket.fd < 0)
            transport();
        if (::connect(socket.fd, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) !=
            0) {
            if (errno != EINPROGRESS)
                transport();
            wait(POLLOUT);
            int error = 0;
            socklen_t size = sizeof(error);
            if (::getsockopt(socket.fd, SOL_SOCKET, SO_ERROR, &error, &size) != 0 || error != 0)
                transport();
        }
        if (!context)
            return;
        ssl.reset(SSL_new(context));
        if (!ssl || X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl.get()), host.c_str()) != 1)
            transport();
        BIO *bio = BIO_new(socket_method());
        if (!bio)
            transport();
        BIO_set_data(bio, &socket.fd);
        SSL_set_bio(ssl.get(), bio, bio); // SSL owns it; descriptor remains ours
        for (;;) {
            check_time();
            ERR_clear_error();
            int result = SSL_connect(ssl.get());
            if (result == 1)
                break;
            ssl_wait(SSL_get_error(ssl.get(), result));
        }
        if (SSL_get_verify_result(ssl.get()) != X509_V_OK ||
            SSL_version(ssl.get()) != TLS1_3_VERSION)
            transport();
        const unsigned char *selected = nullptr;
        unsigned int count = 0;
        SSL_get0_alpn_selected(ssl.get(), &selected, &count);
        if (count != 0 &&
            std::string_view(reinterpret_cast<const char *>(selected), count) != "http/1.1")
            transport();
    }
    void write(std::string_view bytes) {
        while (!bytes.empty()) {
            check_time();
            std::size_t n = 0;
            if (ssl) {
                ERR_clear_error();
                int result = SSL_write_ex(ssl.get(), bytes.data(), bytes.size(), &n);
                if (result != 1) {
                    ssl_wait(SSL_get_error(ssl.get(), result));
                    continue;
                }
            } else {
                auto result = ::send(socket.fd, bytes.data(), bytes.size(), MSG_NOSIGNAL);
                if (result < 0) {
                    if (errno == EINTR)
                        continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        wait(POLLOUT);
                        continue;
                    }
                    transport();
                }
                n = static_cast<std::size_t>(result);
            }
            if (n == 0)
                transport();
            bytes.remove_prefix(n);
        }
    }
    std::size_t read(char *bytes, std::size_t count) {
        for (;;) {
            check_time();
            if (ssl) {
                ERR_clear_error();
                std::size_t n = 0;
                int result = SSL_read_ex(ssl.get(), bytes, count, &n);
                if (result == 1)
                    return n;
                int error = SSL_get_error(ssl.get(), result);
                if (error == SSL_ERROR_ZERO_RETURN)
                    return 0;
                ssl_wait(error);
            } else {
                auto n = ::recv(socket.fd, bytes, count, 0);
                if (n >= 0)
                    return static_cast<std::size_t>(n);
                if (errno == EINTR)
                    continue;
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    transport();
                wait(POLLIN);
            }
        }
    }
};
} // namespace

struct Client::Impl {
    Config config;
    sockaddr_in address{};
    Context context{nullptr, SSL_CTX_free};
    explicit Impl(const Config &input) : config(input) {
        in_addr ip{};
        if (::inet_pton(AF_INET, config.host.c_str(), &ip) != 1 ||
            config.host.find('\0') != std::string::npos)
            invalid("yamora: numeric private IPv4 address required");
        auto value = ntohl(ip.s_addr);
        bool private_ip = (value >> 24U) == 127 || (value >> 24U) == 10 ||
                          (value >> 20U) == 0xac1 || (value >> 16U) == 0xc0a8;
        if (!private_ip || config.port < 1 || config.port > 65535)
            invalid("yamora: invalid endpoint");
        if (config.timeout.count() < 1 || config.timeout.count() > 30000)
            invalid("yamora: timeout must be 1..30000 ms");
        if (!config.document_limit || config.document_limit > max_document_bytes ||
            !config.request_limit || config.request_limit > max_request_bytes ||
            !config.response_limit || config.response_limit > max_response_bytes)
            invalid("yamora: invalid byte limits");
        for (const auto *token : {&config.read_token, &config.write_token}) {
            if (!token->empty() && (token->size() < 32 || token->size() > 512 ||
                                    !std::all_of(token->begin(), token->end(), [](unsigned char c) {
                                        return c >= 33 && c <= 126;
                                    })))
                invalid("yamora: invalid credential");
        }
        address.sin_family = AF_INET;
        address.sin_port = htons(static_cast<std::uint16_t>(config.port));
        address.sin_addr = ip;
        if (!config.tls)
            return;
        const TLS tls = *config.tls;
        config.tls.reset(); // retain only the private immutable OpenSSL context
        for (const auto *path : {&tls.ca_file, &tls.certificate_file, &tls.private_key_file})
            if (path->find('\0') != std::string::npos)
                invalid("yamora: invalid TLS file path");
        if (tls.certificate_file.empty() != tls.private_key_file.empty())
            invalid("yamora: certificate and key must be paired");
        context.reset(SSL_CTX_new(TLS_client_method()));
        if (!context || SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
            SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION) != 1)
            transport();
        SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
        // Encrypted key files fail without interactive password prompts.
        SSL_CTX_set_default_passwd_cb(context.get(), [](char *, int, int, void *) { return 0; });
        if (tls.ca_file.empty()) {
            if (SSL_CTX_set_default_verify_paths(context.get()) != 1)
                transport();
        } else if (SSL_CTX_load_verify_locations(context.get(), tls.ca_file.c_str(), nullptr) != 1)
            transport();
        if (!tls.certificate_file.empty() &&
            (SSL_CTX_use_certificate_chain_file(context.get(), tls.certificate_file.c_str()) != 1 ||
             SSL_CTX_use_PrivateKey_file(context.get(), tls.private_key_file.c_str(),
                                         SSL_FILETYPE_PEM) != 1 ||
             SSL_CTX_check_private_key(context.get()) != 1))
            transport();
        static const unsigned char alpn[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        if (SSL_CTX_set_alpn_protos(context.get(), alpn, sizeof(alpn)) != 0)
            transport();
        SSL_CTX_set_session_cache_mode(context.get(), SSL_SESS_CACHE_OFF);
    }

    Response request(std::string_view method, const std::string &path, std::string_view body,
                     std::string_view media, const std::string &headers, bool write,
                     std::size_t maximum, int status = 200, int alternate = 0,
                     std::string_view expected_revision = {},
                     const detail::Control *outer = nullptr, bool *dispatched = nullptr) const {
        revision_option(expected_revision);
        if (body.size() > config.request_limit)
            invalid("yamora: request exceeds limit");
        bool attempted = false;
        detail::Control standalone{detail::Control::Clock::now() + config.timeout, {}};
        const auto &control = outer ? *outer : standalone;
        try {
            control.check();
            Connection connection(control);
            connection.connect(address, context.get(), config.host);
            std::string head = std::string(method) + " " + path +
                               " HTTP/1.1\r\nHost: " + config.host + ":" +
                               std::to_string(config.port) +
                               "\r\nConnection: close\r\nAccept: application/json, "
                               "application/yaml, text/plain\r\nAccept-Encoding: identity\r\n";
            const auto &token = write ? config.write_token : config.read_token;
            if (!token.empty())
                head += "Authorization: Bearer " + token + "\r\n";
            if (!media.empty() && media != "raw-yaml")
                head += "Content-Type: " + std::string(media) + "\r\n";
            if (!body.empty())
                head += "Content-Length: " + std::to_string(body.size()) + "\r\n";
            head += headers + "\r\n";
            control.check();
            attempted = write;
            if (dispatched)
                *dispatched = true;
            connection.write(head);
            connection.write(body);
            // Fixed memory header budget, independent of body size or peer framing.
            std::string raw;
            std::array<char, 4096> buffer{};
            std::size_t boundary;
            while ((boundary = raw.find("\r\n\r\n")) == std::string::npos) {
                if (raw.size() >= 16 * 1024)
                    protocol("yamora: response headers exceed limit");
                auto n =
                    connection.read(buffer.data(), std::min(buffer.size(), 16 * 1024 - raw.size()));
                if (n == 0)
                    protocol("yamora: truncated response headers");
                raw.append(buffer.data(), n);
            }
            auto line_end = raw.find("\r\n");
            std::string_view line(raw.data(), line_end);
            if (line.size() < 13 || line.substr(0, 9) != "HTTP/1.1 " || line[12] != ' ' ||
                line[9] < '1' || line[9] > '5' || line[10] < '0' || line[10] > '9' ||
                line[11] < '0' || line[11] > '9' ||
                !std::all_of(line.begin(), line.end(),
                             [](unsigned char c) { return c >= 32 && c <= 126; }))
                protocol("yamora: invalid HTTP status line");
            Response response;
            response.status = (line[9] - '0') * 100 + (line[10] - '0') * 10 + line[11] - '0';
            std::map<std::string, std::string> fields;
            std::size_t cursor = line_end + 2, header_count = 0;
            while (cursor < boundary) {
                line_end = raw.find("\r\n", cursor);
                auto colon = raw.find(':', cursor);
                if (colon == std::string::npos || colon >= line_end || colon == cursor ||
                    ++header_count > 64)
                    protocol("yamora: invalid response headers");
                auto key = lower(raw.substr(cursor, colon - cursor));
                if (!std::all_of(key.begin(), key.end(), [](unsigned char c) {
                        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                               (c != 0 && std::strchr("!#$%&'*+-.^_`|~", c) != nullptr);
                    }))
                    protocol("yamora: invalid response header name");
                auto value = trim(std::string_view(raw.data() + colon + 1, line_end - colon - 1));
                if (!std::all_of(value.begin(), value.end(),
                                 [](unsigned char c) { return c >= 32 && c <= 126; }))
                    protocol("yamora: invalid response header");
                // The native diagnostics currently emit this exact duplicate.
                // No identity/framing duplicates or conflicting policy allowed.
                if (!fields.emplace(key, std::string(value)).second &&
                    !(outer && key == "cache-control" && value == "no-store" &&
                      fields.at(key) == "no-store"))
                    protocol("yamora: duplicate response header");
                cursor = line_end + 2;
            }
            if (fields.count("transfer-encoding") || fields.count("content-encoding") ||
                fields.count("upgrade"))
                protocol("yamora: unsupported response encoding");
            auto length = length_value(fields["content-length"]);
            if (response.status != status && (alternate == 0 || response.status != alternate)) {
                // Never expose remote error bodies or redirect locations. Do not
                // consume a potentially unbounded error body; closing is enough.
                bool uncertain = write && (response.status >= 500 || response.status == 408 ||
                                           response.status < 400);
                throw Error(ErrorKind::http, "yamora: HTTP request rejected", response.status,
                            uncertain);
            }
            maximum = std::min(maximum, config.response_limit);
            if (length > maximum)
                protocol("yamora: response exceeds limit");
            response.body = raw.substr(boundary + 4);
            if (response.body.size() > length)
                protocol("yamora: bytes exceed response length");
            while (response.body.size() < length) {
                auto n = connection.read(buffer.data(),
                                         std::min(buffer.size(), length - response.body.size()));
                if (n == 0)
                    protocol("yamora: truncated response body");
                response.body.append(buffer.data(), n);
            }
            response.revision = fields["x-yamldb-revision"];
            if (!hex(response.revision, 16) ||
                (!expected_revision.empty() && expected_revision != response.revision))
                protocol("yamora: invalid or changed revision");
            if (fields.count("etag")) {
                const auto &etag = fields.at("etag");
                if (etag.size() != 18 || etag.front() != '"' || etag.back() != '"' ||
                    !hex(std::string_view(etag).substr(1, 16), 16))
                    protocol("yamora: invalid document ETag");
                response.etag = etag.substr(1, 16);
            }
            if (status != 204) {
                auto type =
                    lower(std::string(trim(std::string_view(fields["content-type"])
                                               .substr(0, fields["content-type"].find(';')))));
                bool yaml = media == "raw-yaml";
                if ((yaml && (type != "application/yaml" && type != "text/yaml")) ||
                    (!yaml && type != (path == "/metrics" ? "text/plain" : "application/json")))
                    protocol("yamora: unexpected response media type");
                if (!yaml && !utf8(response.body, &control))
                    protocol("yamora: invalid UTF-8 response");
                if (yaml && response.etag.empty())
                    protocol("yamora: missing document ETag");
            }
            control.check();
            return response;
        } catch (const Error &error) {
            if (!outer && error.kind() == ErrorKind::deadline)
                throw Error(ErrorKind::transport, "yamora: connection, TLS or deadline failure", 0,
                            attempted);
            if (attempted && error.kind() != ErrorKind::http)
                throw Error(error.kind(), error.what(), error.status(), true);
            throw;
        }
    }
};

Client::Client(const Config &config) : impl_(std::make_shared<Impl>(config)) {}
Document Client::get(std::string_view collection, std::string_view document,
                     std::string_view revision) const {
    // raw-yaml is an internal response selector, never a wire content type.
    auto response = impl_->request("GET", document_path(collection, document), {}, "raw-yaml", {},
                                   false, impl_->config.document_limit, 200, 0, revision);
    return {std::move(response.body), std::move(response.etag), std::move(response.revision)};
}
Response Client::put(std::string_view collection, std::string_view document,
                     std::string_view source, const WriteOptions &options) const {
    auto path = document_path(collection, document);
    auto headers = conditions(options, true);
    if (source.empty() || source.size() > impl_->config.document_limit || !utf8(source))
        invalid("yamora: invalid YAML size or UTF-8");
    return impl_->request("PUT", path, source, "application/yaml", headers, true,
                          impl_->config.document_limit, 200, 201);
}
Response Client::patch(std::string_view collection, std::string_view document,
                       std::string_view json, const WriteOptions &options) const {
    auto path = document_path(collection, document);
    auto headers = conditions(options, false);
    json_input(json, impl_->config.request_limit);
    return impl_->request("PATCH", path, json, "application/json", headers, true,
                          impl_->config.document_limit);
}
Response Client::erase(std::string_view collection, std::string_view document,
                       const WriteOptions &options) const {
    return impl_->request("DELETE", document_path(collection, document), {}, {},
                          conditions(options, false), true, 0, 204);
}
Response Client::documents(std::string_view collection, int limit, std::string_view after,
                           std::string_view revision) const {
    identifier(collection);
    if (limit < 1 || limit > 1000)
        invalid("yamora: invalid document page limit");
    std::string path =
        "/v1/collections/" + std::string(collection) + "/documents?limit=" + std::to_string(limit);
    if (!after.empty()) {
        identifier(after);
        path += "&after=" + std::string(after);
    }
    return impl_->request("GET", path, {}, {}, {}, false, max_response_bytes, 200, 0, revision);
}
Response Client::require_replication_source() const {
    detail::Control control{detail::Control::Clock::now() + impl_->config.timeout, {}};
    auto reply = call(Operation::ready);
    auto ready = detail::decode(reply.body, control);
    if (auto allowed = ready.optional("replication_policy_free")) {
        if (!allowed->boolean_value())
            throw Error(ErrorKind::schema_policy_replication_unsupported,
                        "yamora: schema_policy_replication_unsupported", 409);
    }
    return reply;
}
Response Client::call(Operation operation, std::string_view json,
                      const CallOptions &options) const {
    std::string path, method = "GET";
    bool write = false, collection = false, job = false, changes = false, catalog = false;
    int status = 200;
    std::size_t maximum = max_response_bytes, request_maximum = 2 * 1024 * 1024;
    switch (operation) {
    case Operation::health:
        path = "/healthz";
        break;
    case Operation::ready:
        path = "/readyz";
        break;
    case Operation::stats:
        path = "/v1/stats";
        break;
    case Operation::metrics:
        path = "/metrics";
        maximum = max_document_bytes;
        break;
    case Operation::collections:
        path = "/v1/collections";
        break;
    case Operation::indexes:
        path = "/v1/indexes";
        break;
    case Operation::set_indexes:
        path = "/v1/indexes";
        method = "PUT";
        write = catalog = true;
        break;
    case Operation::start_index_build:
        path = "/v1/index-builds";
        method = "POST";
        write = catalog = true;
        status = 202;
        break;
    case Operation::index_build:
        path = "/v1/index-builds";
        job = true;
        break;
    case Operation::cancel_index_build:
        path = "/v1/index-builds";
        job = write = true;
        method = "DELETE";
        status = 202;
        break;
    case Operation::query:
        path = "/v1/query/";
        method = "POST";
        collection = true;
        break;
    case Operation::aggregate:
        path = "/v1/aggregate/";
        method = "POST";
        collection = true;
        break;
    case Operation::search:
        path = "/v1/search/";
        method = "POST";
        collection = true;
        break;
    case Operation::transaction:
        path = "/v1/transactions";
        method = "POST";
        write = true;
        request_maximum = max_request_bytes;
        break;
    case Operation::changes:
        path = "/v1/changes";
        changes = true;
        break;
    case Operation::replication_status:
        path = "/v1/replication/status";
        break;
    case Operation::replication_begin:
        path = "/v1/replication/begin";
        method = "POST";
        write = true;
        break;
    case Operation::replication_apply:
        path = "/v1/replication/apply";
        method = "POST";
        write = true;
        request_maximum = max_request_bytes;
        break;
    case Operation::replication_commit:
        path = "/v1/replication/commit";
        method = "POST";
        write = true;
        break;
    case Operation::replication_abort:
        path = "/v1/replication/abort";
        method = "POST";
        write = true;
        break;
    case Operation::follow_begin:
        path = "/v1/replication/follow/begin";
        method = "POST";
        write = true;
        break;
    case Operation::follow_apply:
        path = "/v1/replication/follow/apply";
        method = "POST";
        write = true;
        request_maximum = max_request_bytes;
        break;
    case Operation::follow_commit:
        path = "/v1/replication/follow/commit";
        method = "POST";
        write = true;
        break;
    case Operation::follow_abort:
        path = "/v1/replication/follow/abort";
        method = "POST";
        write = true;
        break;
    case Operation::cluster_leader:
        path = "/v1/cluster/leader";
        break;
    case Operation::cluster_status:
        path = "/v1/cluster/status";
        break;
    default:
        invalid("yamora: unsupported operation");
    }
    revision_option(options.revision);
    request_id(options.request_id);
    if (collection) {
        identifier(options.collection);
        path += options.collection;
    } else if (!options.collection.empty())
        invalid("yamora: unexpected collection option");
    if (job) {
        if (options.job_id.empty() && write)
            invalid("yamora: job ID required");
        if (!options.job_id.empty()) {
            if (!hex(options.job_id, 32))
                invalid("yamora: invalid job ID");
            path += "/" + options.job_id;
        }
    } else if (!options.job_id.empty())
        invalid("yamora: unexpected job option");
    if (changes) {
        if (options.limit < 1 || options.limit > 100)
            invalid("yamora: invalid feed limit");
        if (!options.after.empty()) {
            auto token = std::string_view(options.after);
            if (token.size() != 52 || token.substr(0, 3) != "v1." || token[35] != '.' ||
                !hex(token.substr(3, 32), 32) || !hex(token.substr(36), 16))
                invalid("yamora: invalid feed token");
            path += "?after=" + options.after + "&limit=" + std::to_string(options.limit);
        }
    } else if (!options.after.empty() || options.limit != 100)
        invalid("yamora: unexpected feed options");
    if (!write && !options.request_id.empty())
        invalid("yamora: request identity on a read");
    std::string headers;
    if (write && !options.request_id.empty())
        headers += "X-Yamora-Request-Id: " + options.request_id + "\r\n";
    if (catalog && !options.revision.empty())
        headers += "If-Match: \"" + options.revision + "\"\r\n";
    // Other writes embed revision conditions in their raw JSON body.
    if (write && !catalog && !options.revision.empty())
        invalid("yamora: put mutation revision in its JSON body");
    if (method == "POST" || method == "PUT")
        json_input(json, std::min(request_maximum, impl_->config.request_limit));
    else if (!json.empty())
        invalid("yamora: body on a bodyless operation");
    return impl_->request(method, path, json, json.empty() ? "" : "application/json", headers,
                          write, maximum, status, 0,
                          catalog ? std::string_view{} : options.revision);
}
} // namespace yamora

namespace yamora {
Response Client::exchange(std::string_view method, const std::string &path, std::string_view body,
                          std::string_view media, const std::string &headers, bool write,
                          std::size_t maximum, int status, int alternate, std::string_view revision,
                          const detail::Control &control, bool &dispatched) const {
    return impl_->request(method, path, body, media, headers, write, maximum, status, alternate,
                          revision, &control, &dispatched);
}
} // namespace yamora
