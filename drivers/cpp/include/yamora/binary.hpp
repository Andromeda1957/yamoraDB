#pragma once
#include "client.hpp"
#include <cstdint>
#include <optional>
#include <functional>

namespace yamora {
// Only static PEM material is accepted. Construction parses it into private
// OpenSSL objects; neither caller paths nor caller SSL_CTX objects are
// retained.
struct BinaryConfig {
  std::string host = "127.0.0.1";
  int port = 7401;
  std::string server_identity =
      "127.0.0.1";                    // SAN IP or DNS identity, never routing
  std::string ca_pem;                 // required, 1..32 certificates, <=64 KiB
  std::string client_certificate_pem; // optional chain, <=8 certificates/64 KiB
  std::string client_private_key_pem; // matching unencrypted key, <=64 KiB
  std::chrono::milliseconds timeout{5000};
  std::size_t max_frame_bytes = 65536;  // 4096..65536
  std::size_t max_concurrent_calls = 4; // 1..4, shared by copies of this client
};
enum class BinaryMethod : std::uint8_t {
  get = 1,
  head = 2,
  put = 3,
  erase = 4
};
struct BinaryOptions {
  // Presence matters: empty present conditions reach native validation.
  std::optional<std::string> if_match;
  std::optional<std::string> if_none_match;
  std::optional<std::string>
      request_id; // nonzero 32 lowercase hex; mutations generate if absent
};
class BinaryClient;
// No credentials or borrowed buffers. Accessors return defensive copies;
// copies of an envelope share privately owned, const operation data.
class BinaryEnvelope {
public:
  BinaryEnvelope(const BinaryEnvelope &) = default;
  BinaryEnvelope &operator=(const BinaryEnvelope &) = default;
  BinaryMethod method() const noexcept;
  std::string collection() const;
  std::string document() const;
  std::string source() const;
  BinaryOptions options() const;

private:
  friend class BinaryClient;
  struct Data;
  explicit BinaryEnvelope(std::shared_ptr<const Data> data)
      : data_(std::move(data)) {}
  std::shared_ptr<const Data> data_;
};
class BinaryUncertainWriteError : public Error {
public:
  BinaryUncertainWriteError(BinaryEnvelope envelope, ErrorKind kind,
                            int status = 0);
  const BinaryEnvelope &envelope() const noexcept { return envelope_; }

private:
  friend class BinaryClient;
  void failure(ErrorKind kind, int status = 0) noexcept {
    outcome(kind, status, true);
  }
  BinaryEnvelope envelope_;
};
struct BinaryResponse {
  int status = 0;
  std::string content_type, body, revision, etag; // etag is unquoted
  std::uint64_t representation_length = 0;
  std::optional<std::string> collection, document, request_id;
  std::optional<std::uint8_t> allow, authenticate;
  std::optional<std::uint32_t> retry_after_seconds;
};
// Owned raw schema-2 logical request. No credentials or caller memory survive.
class BinaryOperation {
public:
  std::string method() const;
  std::string target() const;
  std::string content_type() const;
  std::string source() const;
  BinaryOptions options() const;
private:
  friend class BinaryClient;
  struct Data;
  explicit BinaryOperation(std::shared_ptr<const Data> data) : data_(std::move(data)) {}
  std::shared_ptr<const Data> data_;
};
class BinaryUnsupportedPeerError : public Error {
public:
  BinaryUnsupportedPeerError() : Error(ErrorKind::protocol, "yamora: peer lacks binary operations") {}
};
class BinaryOperationError : public Error {
public:
  std::optional<BinaryOperation> envelope() const { return uncertain() ? std::optional<BinaryOperation>(original_) : std::nullopt; }
  const std::optional<BinaryResponse> &response() const noexcept { return state_->response; }
  const std::string &last_after() const noexcept { return state_->after; }
private:
  friend class BinaryClient;
  struct State {
    std::optional<BinaryResponse> response;
    std::string after;
    explicit State(std::string cursor) : after(std::move(cursor)) {}
  };
  explicit BinaryOperationError(BinaryOperation original, std::string after)
      : Error(ErrorKind::transport, "yamora: binary operation failed"), original_(std::move(original)), state_(std::make_shared<State>(std::move(after))) {}
  BinaryOperation original_;
  std::shared_ptr<State> state_;
  void failure(ErrorKind kind, int status, bool uncertain) noexcept { outcome(kind, status, uncertain); }
};
struct BinaryFeedResult {
  BinaryResponse response;
  std::string last_after;
};
// Synchronous, thread safe source CRUD and additive operations. Each call owns one
// new verified TLS 1.3 connection. No retries, DNS, proxies or discovery.
class BinaryClient {
public:
  explicit BinaryClient(const BinaryConfig &config);
  BinaryResponse get(std::string_view collection, std::string_view document,
                     std::string_view bearer = {},
                     const BinaryOptions &options = {},
                     const RequestOptions &request = {}) const;
  BinaryResponse head(std::string_view collection, std::string_view document,
                      std::string_view bearer = {},
                      const BinaryOptions &options = {},
                      const RequestOptions &request = {}) const;
  BinaryResponse put(std::string_view collection, std::string_view document,
                     std::string_view source, std::string_view bearer = {},
                     const BinaryOptions &options = {},
                     const RequestOptions &request = {}) const;
  BinaryResponse erase(std::string_view collection, std::string_view document,
                       std::string_view bearer = {},
                       const BinaryOptions &options = {},
                       const RequestOptions &request = {}) const;
  BinaryResponse execute(const BinaryEnvelope &envelope,
                         std::string_view bearer = {},
                         const RequestOptions &request = {}) const;
  BinaryResponse operation(std::string_view method, std::string_view target,
                           std::string_view content_type, std::string_view specification,
                           std::string_view bearer = {}, const BinaryOptions &options = {},
                           const RequestOptions &request = {}) const;
  // Callback sees one complete validated raw page including LF. The next read
  // waits for callback return; retain the supplied bytes by copying if needed.
  BinaryFeedResult feed(std::string_view target,
                       const std::function<void(std::string_view)> &consume,
                       std::string_view bearer = {}, const BinaryOptions &options = {},
                       const RequestOptions &request = {}) const;

private:
  BinaryResponse call(BinaryMethod method, std::string_view collection,
                      std::string_view document, std::string_view source,
                      std::string_view bearer, const BinaryOptions &options,
                      const RequestOptions &request,
                      const BinaryEnvelope *replay) const;
  BinaryFeedResult operation_call(std::string_view method, std::string_view target,
                       std::string_view content_type, std::string_view source,
                       std::string_view bearer, const BinaryOptions &options,
                       const RequestOptions &request,
                       const std::function<void(std::string_view)> *consume) const;
  struct Impl;
  std::shared_ptr<Impl> impl_;
};
} // namespace yamora
