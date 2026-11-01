#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yamora {
inline constexpr std::size_t max_document_bytes = 16 * 1024 * 1024;
inline constexpr std::size_t max_request_bytes = 64 * 1024 * 1024;
inline constexpr std::size_t max_response_bytes = 64 * 1024 * 1024;

struct TLS {
    // Empty CA path uses system trust. Peer IP verification is always required.
    std::string ca_file;
    std::string certificate_file;
    std::string private_key_file;
};
struct Config {
    std::string host = "127.0.0.1";
    int port = 8765;
    std::string read_token;
    std::string write_token;
    std::chrono::milliseconds timeout{5000};
    std::shared_ptr<const TLS> tls; // copied on construction; null selects HTTP
    std::size_t document_limit = max_document_bytes;
    std::size_t request_limit = max_request_bytes;
    std::size_t response_limit = max_response_bytes;
};
enum class ErrorKind {
    invalid_argument,
    transport,
    protocol,
    http,
    cancelled,
    deadline,
    allocation,
    schema_policy_replication_unsupported
};
namespace detail {
struct Control;
}
class ClusterClient;
class Error : public std::runtime_error {
  public:
    Error(ErrorKind kind, const char *message, int status = 0, bool uncertain = false);
    ErrorKind kind() const noexcept { return kind_; }
    int status() const noexcept { return status_; }
    // Conservative: mutation was attempted and its commit is not established.
    bool uncertain() const noexcept { return uncertain_; }

  protected:
    void outcome(ErrorKind kind, int status, bool uncertain) noexcept {
        kind_ = kind;
        status_ = status;
        uncertain_ = uncertain;
    }

  private:
    ErrorKind kind_;
    int status_;
    bool uncertain_;
};
struct Response {
    int status = 0;
    std::string body;     // exact raw JSON (or metrics); not parsed or reserialized
    std::string revision; // validated 16 lowercase hex snapshot revision
    std::string etag;     // unquoted content ETag, if supplied by server
};
struct Document {
    std::string source; // exact authored YAML, including CRLF/comments
    std::string etag;
    std::string revision;
};
struct WriteOptions {
    std::string etag;         // unquoted 16 lowercase hex
    bool create_only = false; // PUT only
    std::string request_id;   // optional nonzero 32 lowercase hex, never generated
};

// Raw JSON operations; response schemas and server-side validation are
// described in README.md. No arbitrary URL, method, path, header, redirect or
// retry API.
enum class Operation {
    health,
    ready,
    stats,
    metrics,
    collections,
    indexes,
    set_indexes,
    start_index_build,
    index_build,
    cancel_index_build,
    query,
    aggregate,
    search,
    transaction,
    changes,
    replication_status,
    replication_begin,
    replication_apply,
    replication_commit,
    replication_abort,
    follow_begin,
    follow_apply,
    follow_commit,
    follow_abort,
    cluster_leader,
    cluster_status
};
struct CallOptions {
    std::string collection; // query/aggregate/search
    std::string job_id;     // index_build (optional), cancel_index_build (required)
    std::string after;      // changes cursor: v1.<32 hex>.<16 hex>
    int limit = 100;        // changes only, 1..100
    std::string revision;   // catalog mutation If-Match; other calls check response
    std::string request_id; // mutation operations only
};
class Client {
  public:
    explicit Client(const Config &config = {});
    Document get(std::string_view collection, std::string_view document,
                 std::string_view revision = {}) const;
    Response put(std::string_view collection, std::string_view document, std::string_view source,
                 const WriteOptions &options = {}) const;
    Response patch(std::string_view collection, std::string_view document, std::string_view json,
                   const WriteOptions &options = {}) const;
    Response erase(std::string_view collection, std::string_view document,
                   const WriteOptions &options = {}) const;
    Response documents(std::string_view collection, int limit = 1000, std::string_view after = {},
                       std::string_view revision = {}) const;
    Response call(Operation operation, std::string_view json = {},
                  const CallOptions &options = {}) const;
    // Advisory source preflight before application-owned stages. Native transfer
    // admission remains authoritative; old policy-free servers may omit the field.
    Response require_replication_source() const;

  private:
    friend class ClusterClient;
    Response exchange(std::string_view method, const std::string &path, std::string_view body,
                      std::string_view media, const std::string &headers, bool write,
                      std::size_t maximum, int status, int alternate, std::string_view revision,
                      const detail::Control &control, bool &dispatched) const;
    struct Impl;
    std::shared_ptr<const Impl> impl_;
};
// One-way cooperative cancellation; no thread or descriptor is closed by
// cancel().
class Cancellation {
  public:
    void cancel() noexcept { cancelled_.store(true, std::memory_order_release); }
    bool cancelled() const noexcept { return cancelled_.load(std::memory_order_acquire); }

  private:
    std::atomic<bool> cancelled_{false};
};
struct RequestOptions {
    std::shared_ptr<const Cancellation> cancellation;
    // Zero uses ClusterConfig.timeout; a positive value can only shorten it.
    std::chrono::milliseconds timeout{0};
};
struct ClusterSeed {
    std::string host;
    int port;
    int node;
};
struct ClusterConfig {
    std::vector<ClusterSeed> seeds;
    std::string cluster_id; // expected nonzero feed identity, 32 lowercase hex
    int voters = 3;
    std::shared_ptr<const TLS> tls; // required; copied at construction
    std::string read_token;
    std::string write_token;
    std::chrono::milliseconds timeout{5000};
    std::chrono::milliseconds attempt_timeout{1000};
    std::size_t document_limit = max_document_bytes;
    std::size_t request_limit = max_request_bytes;
    std::size_t response_limit = max_response_bytes;
};
// Immutable request inputs, without credentials. Copies share owned frozen
// bytes.
class PreparedMutation {
  public:
    const std::string &request_id() const noexcept;
    const std::string &method() const noexcept;
    const std::string &path() const noexcept;
    const std::string &body() const noexcept;
    const std::string &etag() const noexcept;
    bool create_only() const noexcept;
    std::size_t operation_count() const noexcept;

  private:
    friend class ClusterClient;
    struct Data;
    explicit PreparedMutation(std::shared_ptr<const Data> data) : data_(std::move(data)) {}
    std::shared_ptr<const Data> data_;
};
class UncertainWriteError : public Error {
  public:
    explicit UncertainWriteError(PreparedMutation mutation);
    const PreparedMutation &mutation() const noexcept { return mutation_; }
    const std::string &request_id() const noexcept { return mutation_.request_id(); }

  private:
    friend class ClusterClient;
    void failure(ErrorKind kind, int status) noexcept { outcome(kind, status, true); }
    PreparedMutation mutation_;
};
// HTTPS seeds are the entire credential destination trust set. Native status
// has no UUID attestation: the caller must bind CA/IP/seed policy to its
// cluster.
class ClusterClient {
  public:
    explicit ClusterClient(const ClusterConfig &config);
    Document get(std::string_view collection, std::string_view document,
                 std::string_view revision = {}, const RequestOptions &request = {}) const;
    Response documents(std::string_view collection, int limit = 1000, std::string_view after = {},
                       std::string_view revision = {}, const RequestOptions &request = {}) const;
    Response put(std::string_view collection, std::string_view document, std::string_view source,
                 const WriteOptions &options = {}, const RequestOptions &request = {}) const;
    Response patch(std::string_view collection, std::string_view document, std::string_view json,
                   const WriteOptions &options = {}, const RequestOptions &request = {}) const;
    Response erase(std::string_view collection, std::string_view document,
                   const WriteOptions &options = {}, const RequestOptions &request = {}) const;
    Response call(Operation operation, std::string_view json = {}, const CallOptions &options = {},
                  const RequestOptions &request = {}) const;
    PreparedMutation prepare_put(std::string_view collection, std::string_view document,
                                 std::string_view source, const WriteOptions &options = {}) const;
    PreparedMutation prepare_patch(std::string_view collection, std::string_view document,
                                   std::string_view json, const WriteOptions &options = {}) const;
    PreparedMutation prepare_erase(std::string_view collection, std::string_view document,
                                   const WriteOptions &options = {}) const;
    PreparedMutation prepare_call(Operation operation, std::string_view json,
                                  const CallOptions &options = {}) const;
    Response execute(const PreparedMutation &mutation, const RequestOptions &request = {}) const;

  private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};
} // namespace yamora
