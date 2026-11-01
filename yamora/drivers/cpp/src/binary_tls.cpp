#include "binary_tls.hpp"
#include <cerrno>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <sys/socket.h>
#include <unistd.h>

namespace yamora::binary_detail {
sockaddr_in address(std::string_view host, int port) {
  if (host.size() > 15 || host.find('\0') != std::string_view::npos ||
      port < 1 || port > 65535)
    invalid();
  sockaddr_in result{};
  std::string owned(host);
  if (::inet_pton(AF_INET, owned.c_str(), &result.sin_addr) != 1)
    invalid();
  auto value = ntohl(result.sin_addr.s_addr);
  if (!((value >> 24U) == 127 || (value >> 24U) == 10 ||
        (value >> 20U) == 0xac1 || (value >> 16U) == 0xc0a8))
    invalid();
  result.sin_family = AF_INET;
  result.sin_port = htons(static_cast<std::uint16_t>(port));
  return result;
}
void server_identity(std::string_view identity) {
  if (identity.empty() || identity.size() > 253)
    invalid();
  if (identity.find_first_not_of("0123456789.") == std::string_view::npos) {
    in_addr ip{};
    if (::inet_pton(AF_INET, std::string(identity).c_str(), &ip) != 1)
      invalid();
    return;
  }
  while (!identity.empty()) {
    auto dot = identity.find('.');
    auto label = identity.substr(0, dot);
    if (label.empty() || label.size() > 63 || label.front() == '-' ||
        label.back() == '-' ||
        !std::all_of(label.begin(), label.end(), [](unsigned char c) {
          return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '-';
        }))
      invalid();
    if (dot == std::string_view::npos)
      return;
    identity.remove_prefix(dot + 1);
    if (identity.empty())
      invalid();
  }
}
namespace {
using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;
using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;
bool space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
void trim(std::string_view &bytes) {
  while (!bytes.empty() && space(bytes.front()))
    bytes.remove_prefix(1);
}
// Parsing one exact block prevents PEM_read's permissive search past junk.
std::vector<Certificate> certificates(std::string_view bytes,
                                      std::size_t maximum) {
  std::vector<Certificate> result;
  trim(bytes);
  while (!bytes.empty()) {
    constexpr std::string_view begin = "-----BEGIN CERTIFICATE-----",
                               end = "-----END CERTIFICATE-----";
    if (result.size() == maximum || bytes.substr(0, begin.size()) != begin)
      invalid();
    auto finish = bytes.find(end);
    if (finish == std::string_view::npos)
      invalid();
    finish += end.size();
    auto block = bytes.substr(0, finish);
    if (block.find("-----BEGIN ", begin.size()) != std::string_view::npos)
      invalid();
    Bio bio(BIO_new_mem_buf(block.data(), static_cast<int>(block.size())),
            BIO_free);
    if (!bio)
      transport();
    Certificate cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr),
                     X509_free);
    if (!cert)
      invalid();
    result.push_back(std::move(cert));
    bytes.remove_prefix(finish);
    trim(bytes);
  }
  if (result.empty())
    invalid();
  return result;
}
// Socket BIO never changes global signal handlers; SIGPIPE is suppressed only
// for sends on this call's descriptor. Cancellation is polled, no callbacks.
const BIO_METHOD *socket_method() {
  static const std::unique_ptr<BIO_METHOD, decltype(&BIO_meth_free)> method(
      [] {
        auto m = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(),
                              "yamora binary socket");
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
                [](BIO *b, const char *p, int n) {
                  BIO_clear_retry_flags(b);
                  auto count =
                      ::send(*static_cast<int *>(BIO_get_data(b)), p,
                             static_cast<std::size_t>(n), MSG_NOSIGNAL);
                  if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                                    errno == EINTR))
                    BIO_set_retry_write(b);
                  return static_cast<int>(count);
                }) == 1 &&
            BIO_meth_set_read(
                m,
                [](BIO *b, char *p, int n) {
                  BIO_clear_retry_flags(b);
                  auto count = ::recv(*static_cast<int *>(BIO_get_data(b)), p,
                                      static_cast<std::size_t>(n), 0);
                  if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK ||
                                    errno == EINTR))
                    BIO_set_retry_read(b);
                  return static_cast<int>(count);
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
} // namespace
Context context(const BinaryConfig &config) {
  if (config.ca_pem.empty() || config.ca_pem.size() > 65536 ||
      config.client_certificate_pem.size() > 65536 ||
      config.client_private_key_pem.size() > 65536 ||
      config.client_certificate_pem.empty() !=
          config.client_private_key_pem.empty())
    invalid();
  // Only the freshly parsed objects survive construction. No trust-path or
  // environment fallback, callbacks, opaque keys, key loggers or custom BIOs.
  const std::string roots = config.ca_pem,
                    chain = config.client_certificate_pem;
  std::string key = config.client_private_key_pem;
  struct Wipe {
    std::string &key;
    ~Wipe() {
      if (!key.empty())
        OPENSSL_cleanse(key.data(), key.size());
    }
  } wipe{key};
  Context ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
  if (!ctx || SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1 ||
      SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) != 1)
    transport();
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
  SSL_CTX_set_verify_depth(ctx.get(), 8);
  SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);
  SSL_CTX_set_options(ctx.get(), SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);
  if (SSL_CTX_set_max_early_data(ctx.get(), 0) != 1)
    transport();
  const std::string protocols =
      std::string(1, static_cast<char>(alpn.size())) + std::string(alpn);
  if (SSL_CTX_set_alpn_protos(
          ctx.get(), reinterpret_cast<const unsigned char *>(protocols.data()),
          static_cast<unsigned>(protocols.size())) != 0)
    transport();
  auto anchors = certificates(roots, 32);
  for (const auto &cert : anchors)
    if (X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx.get()), cert.get()) != 1)
      invalid();
  if (!chain.empty()) {
    auto certs = certificates(chain, 8);
    if (SSL_CTX_use_certificate(ctx.get(), certs.front().get()) != 1)
      invalid();
    for (std::size_t i = 1; i < certs.size(); ++i)
      if (SSL_CTX_add1_chain_cert(ctx.get(), certs[i].get()) != 1)
        invalid();
    std::string_view bytes(key);
    trim(bytes);
    std::string_view kind;
    for (auto candidate :
         {"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"}) {
      auto prefix = "-----BEGIN " + std::string(candidate) + "-----";
      if (bytes.substr(0, prefix.size()) == prefix)
        kind = candidate;
    }
    if (kind.empty())
      invalid();
    auto suffix = "-----END " + std::string(kind) + "-----";
    auto finish = bytes.find(suffix);
    if (finish == std::string_view::npos ||
        bytes.find("-----BEGIN ", 1) != std::string_view::npos)
      invalid();
    auto tail = bytes.substr(finish + suffix.size());
    trim(tail);
    if (!tail.empty())
      invalid();
    Bio bio(BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size())),
            BIO_free);
    if (!bio)
      transport();
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> private_key(
        PEM_read_bio_PrivateKey(
            bio.get(), nullptr, [](char *, int, int, void *) { return 0; },
            nullptr),
        EVP_PKEY_free);
    if (!private_key ||
        SSL_CTX_use_PrivateKey(ctx.get(), private_key.get()) != 1 ||
        SSL_CTX_check_private_key(ctx.get()) != 1)
      invalid();
  }
  return ctx;
}
Connection::~Connection() {
  tls_.reset();
  if (fd_ >= 0)
    ::close(fd_);
}
void Connection::wait(short events) const {
  for (;;) {
    control_.check();
    auto left = std::chrono::ceil<std::chrono::milliseconds>(
                    control_.deadline - detail::Control::Clock::now())
                    .count();
    pollfd p{fd_, events, 0};
    int result =
        ::poll(&p, 1, static_cast<int>(std::clamp<std::int64_t>(left, 1, 5)));
    if (result > 0) {
      if ((p.revents & POLLNVAL) != 0)
        transport();
      return;
    }
    if (result == 0 || errno == EINTR)
      continue;
    transport();
  }
}
void Connection::ssl_wait(int error) const {
  if (error == SSL_ERROR_WANT_READ)
    wait(POLLIN);
  else if (error == SSL_ERROR_WANT_WRITE)
    wait(POLLOUT);
  else
    transport();
}
void Connection::connect(const sockaddr_in &endpoint, SSL_CTX *ctx,
                         const std::string &identity) {
  control_.check();
  fd_ = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd_ < 0)
    transport();
  if (::connect(fd_, reinterpret_cast<const sockaddr *>(&endpoint),
                sizeof(endpoint)) != 0) {
    if (errno != EINPROGRESS)
      transport();
    wait(POLLOUT);
    int error = 0;
    socklen_t size = sizeof(error);
    if (::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &error, &size) != 0 || error)
      transport();
  }
  tls_.reset(SSL_new(ctx));
  if (!tls_)
    transport();
  in_addr ip{};
  if (::inet_pton(AF_INET, identity.c_str(), &ip) == 1) {
    if (X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(tls_.get()),
                                      identity.c_str()) != 1)
      transport();
  } else {
    X509_VERIFY_PARAM_set_hostflags(SSL_get0_param(tls_.get()),
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS |
                                        X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    if (SSL_set1_host(tls_.get(), identity.c_str()) != 1 ||
        SSL_set_tlsext_host_name(tls_.get(), identity.c_str()) != 1)
      transport();
  }
  BIO *bio = BIO_new(socket_method());
  if (!bio)
    transport();
  BIO_set_data(bio, &fd_);
  SSL_set_bio(tls_.get(), bio, bio);
  for (;;) {
    control_.check();
    ERR_clear_error();
    int result = SSL_connect(tls_.get());
    if (result == 1)
      break;
    ssl_wait(SSL_get_error(tls_.get(), result));
  }
  const unsigned char *selected = nullptr;
  unsigned count = 0;
  SSL_get0_alpn_selected(tls_.get(), &selected, &count);
  if (SSL_get_verify_result(tls_.get()) != X509_V_OK ||
      SSL_version(tls_.get()) != TLS1_3_VERSION ||
      std::string_view(reinterpret_cast<const char *>(selected), count) != alpn)
    transport();
  control_.check();
}
void Connection::write(std::string_view bytes) {
  while (!bytes.empty()) {
    control_.check();
    ERR_clear_error();
    std::size_t n = 0;
    int result = SSL_write_ex(tls_.get(), bytes.data(), bytes.size(), &n);
    if (result != 1) {
      ssl_wait(SSL_get_error(tls_.get(), result));
      continue;
    }
    if (n == 0)
      transport();
    bytes.remove_prefix(n);
  }
}
void Connection::read(char *bytes, std::size_t size) {
  while (size) {
    control_.check();
    ERR_clear_error();
    std::size_t n = 0;
    int result = SSL_read_ex(tls_.get(), bytes, size, &n);
    if (result != 1) {
      ssl_wait(SSL_get_error(tls_.get(), result));
      continue;
    }
    if (n == 0)
      transport();
    bytes += n;
    size -= n;
  }
}
void Connection::send(Kind kind, std::uint32_t stream,
                      std::string_view payload) {
  write(header(kind, stream, payload.size()));
  write(payload);
}
std::pair<FrameHeader, std::string> Connection::receive(std::size_t cap) {
  std::array<char, 16> bytes{};
  read(bytes.data(), bytes.size());
  auto h = decode_header(std::string_view(bytes.data(), bytes.size()), cap);
  // Header validity and negotiated bounds precede every peer-sized allocation.
  std::string payload(h.length, '\0');
  read(payload.data(), payload.size());
  return {h, std::move(payload)};
}
} // namespace yamora::binary_detail
