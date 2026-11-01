#pragma once
#include "binary_wire.hpp"
#include <arpa/inet.h>
#include <openssl/ssl.h>

namespace yamora::binary_detail {
using Context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
sockaddr_in address(std::string_view host, int port);
void server_identity(std::string_view identity);
Context context(const BinaryConfig &config);
class Connection {
  int fd_ = -1;
  std::unique_ptr<SSL, decltype(&SSL_free)> tls_{nullptr, SSL_free};
  const detail::Control &control_;
  void wait(short events) const;
  void ssl_wait(int error) const;

public:
  explicit Connection(const detail::Control &control) : control_(control) {}
  ~Connection();
  Connection(const Connection &) = delete;
  Connection &operator=(const Connection &) = delete;
  void connect(const sockaddr_in &endpoint, SSL_CTX *ctx,
               const std::string &identity);
  void write(std::string_view bytes);
  void read(char *bytes, std::size_t size);
  void send(Kind kind, std::uint32_t stream, std::string_view payload = {});
  std::pair<FrameHeader, std::string> receive(std::size_t cap);
};
} // namespace yamora::binary_detail
