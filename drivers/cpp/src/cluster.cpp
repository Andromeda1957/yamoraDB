#include "control.hpp"
#include "json.hpp"
#include "yamora/client.hpp"
#include <array>
#include <mutex>
#include <openssl/rand.h>
#include <optional>
#include <set>
#include <type_traits>

namespace yamora {
namespace {
using detail::Control;
using detail::Json;
using detail::require;
[[noreturn]] void invalid() {
    throw Error(ErrorKind::invalid_argument, "yamora: invalid cluster argument");
}
bool hex(std::string_view v, std::size_t n) {
    return v.size() == n && std::all_of(v.begin(), v.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
           });
}
bool nonzero(std::string_view v) { return hex(v, 32) && v.find_first_not_of('0') != v.npos; }
void id(std::string_view v) {
    if (v.empty() || v.size() > 128 || !std::all_of(v.begin(), v.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        }))
        invalid();
}
void revision(std::string_view v) {
    if (!v.empty() && !hex(v, 16))
        invalid();
}
void duration(std::chrono::milliseconds v) {
    if (v.count() < 1 || v.count() > 30000)
        invalid();
}
std::string docpath(std::string_view c, std::string_view d, bool write) {
    id(c);
    id(d);
    if (write && c == "yamldb-system")
        invalid();
    return "/v1/collections/" + std::string(c) + "/documents/" + std::string(d);
}
bool token(std::string_view v, std::string_view cluster) {
    return v.size() == 52 && v.substr(0, 3) == "v1." && v[35] == '.' &&
           v.substr(3, 32) == cluster && hex(v.substr(36), 16);
}
std::string generate_id() {
    std::array<unsigned char, 16> bytes{};
    do {
        if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
            throw Error(ErrorKind::transport, "yamora: request identity generation failed");
    } while (std::all_of(bytes.begin(), bytes.end(), [](auto b) { return b == 0; }));
    constexpr char digits[] = "0123456789abcdef";
    std::string value(32, '0');
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        value[i * 2] = digits[bytes[i] >> 4U];
        value[i * 2 + 1] = digits[bytes[i] & 15U];
    }
    return value;
}
Json input_json(std::string_view bytes, std::size_t maximum, const Control &control) {
    if (bytes.size() > maximum || bytes.find("\xc2\x85") != bytes.npos)
        invalid();
    try {
        auto v = detail::decode(bytes, control);
        require(v.type == Json::object);
        return v;
    } catch (const Error &e) {
        if (e.kind() == ErrorKind::protocol)
            invalid();
        throw;
    }
}
void source_valid(std::string_view bytes, std::size_t maximum, const Control &control) {
    if (bytes.empty() || bytes.size() > maximum)
        invalid();
    std::size_t next_check = 0;
    for (std::size_t i = 0; i < bytes.size();) {
        if (i >= next_check) {
            control.check();
            next_check = i + 1024;
        }
        auto c = static_cast<unsigned char>(bytes[i++]);
        if (c < 128) {
            if (!c || (c < 32 && c != 9 && c != 10 && c != 13))
                invalid();
            continue;
        }
        unsigned n, point, minimum;
        if (c >= 0xc2 && c <= 0xdf) {
            n = 1;
            point = c & 31U;
            minimum = 128;
        } else if (c >= 0xe0 && c <= 0xef) {
            n = 2;
            point = c & 15U;
            minimum = 2048;
        } else if (c >= 0xf0 && c <= 0xf4) {
            n = 3;
            point = c & 7U;
            minimum = 65536;
        } else
            invalid();
        if (n > bytes.size() - i)
            invalid();
        for (unsigned j = 0; j < n; ++j) {
            auto b = static_cast<unsigned char>(bytes[i++]);
            if ((b & 0xc0U) != 0x80U)
                invalid();
            point = (point << 6U) | (b & 63U);
        }
        if (point < minimum || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff))
            invalid();
    }
    control.check();
}
struct Spec {
    std::string method = "GET", path, body, media, headers, expected_revision;
    std::string collection, document, etag, request_id;
    bool write = false, create_only = false, supported = true;
    std::size_t maximum = max_response_bytes, count = 0;
    int status = 200, alternate = 0;
};
Json public_json(const Response &r, const Control &control) {
    auto v = detail::decode(r.body, control);
    require(v.type == Json::object);
    if (auto p = v.optional("revision"))
        require(p->str() == r.revision);
    control.check();
    return v;
}
void feed(const Json &v, std::string_view cluster, bool checkpoint) {
    for (const auto key : {"checkpoint", "next_after", "oldest_after"})
        require(token(v.get(key).str(), cluster));
    const auto &items = v.get("transactions").list();
    v.get("has_more").boolean_value();
    if (checkpoint)
        require(items.empty() && !v.get("has_more").boolean_value() &&
                v.get("checkpoint").str() == v.get("next_after").str());
    for (const auto &frame : items)
        require(token(frame.get("token").str(), cluster));
}
void receipt(const Response &r, const Spec &s, const Control &control) {
    if (s.method == "DELETE") {
        require(r.status == 204 && r.body.empty() && (r.etag.empty() || r.etag == r.revision));
        return;
    }
    auto v = public_json(r, control);
    require(v.get("revision").str() == r.revision);
    if (!s.collection.empty()) {
        v.keys({"status", "collection", "document", "revision", "etag"});
        require(v.get("status").str() == "stored" && v.get("collection").str() == s.collection &&
                v.get("document").str() == s.document && hex(v.get("etag").str(), 16) &&
                v.get("etag").str() == r.etag);
        require(s.method == "PUT"
                    ? (s.create_only ? r.status == 201
                                     : (!s.etag.empty() ? r.status == 200
                                                        : (r.status == 200 || r.status == 201)))
                    : r.status == 200);
    } else {
        v.keys({"status", "operations", "revision"});
        require(r.status == 200 && v.get("status").str() == "committed" &&
                v.get("operations").uint() == s.count && (r.etag.empty() || r.etag == r.revision));
    }
    control.check();
}
} // namespace
struct PreparedMutation::Data {
    Spec spec;
    std::string cluster_id;
    // Outcome is separate from immutable inputs. A later rejection must never
    // erase an earlier ambiguous dispatch, including across execute() calls.
    mutable std::atomic<bool> uncertain{false};
    Data(Spec input, std::string cluster)
        : spec(std::move(input)), cluster_id(std::move(cluster)) {}
};
const std::string &PreparedMutation::request_id() const noexcept { return data_->spec.request_id; }
const std::string &PreparedMutation::method() const noexcept { return data_->spec.method; }
const std::string &PreparedMutation::path() const noexcept { return data_->spec.path; }
const std::string &PreparedMutation::body() const noexcept { return data_->spec.body; }
const std::string &PreparedMutation::etag() const noexcept { return data_->spec.etag; }
bool PreparedMutation::create_only() const noexcept { return data_->spec.create_only; }
std::size_t PreparedMutation::operation_count() const noexcept { return data_->spec.count; }
static_assert(std::is_nothrow_copy_constructible<UncertainWriteError>::value,
              "uncertain-write exception copying must not allocate");
UncertainWriteError::UncertainWriteError(PreparedMutation input)
    : Error(ErrorKind::protocol, "yamora: write outcome uncertain; execute original mutation", 0,
            true),
      mutation_(std::move(input)) {}

struct ClusterClient::Impl {
    ClusterConfig config;
    std::vector<Client> endpoints;
    mutable std::mutex mutex;
    int cached = -1;
    std::size_t cursor = 0;
    std::uint64_t generation = 0;
    explicit Impl(const ClusterConfig &input) : config(input) {
        duration(config.timeout);
        duration(config.attempt_timeout);
        if (!config.tls || !nonzero(config.cluster_id) || config.seeds.empty() ||
            config.seeds.size() > 9 || config.voters < 3 || config.voters > 9 ||
            config.voters % 2 == 0)
            invalid();
        // Snapshot TLS before constructing endpoints; caller mutations cannot
        // change later seeds or established contexts.
        config.tls = std::make_shared<const TLS>(*config.tls);
        std::set<std::pair<std::string, int>> seen;
        std::set<int> nodes;
        for (const auto &seed : config.seeds) {
            if (seed.node < 1 || seed.node > config.voters || !nodes.insert(seed.node).second ||
                !seen.emplace(seed.host, seed.port).second)
                invalid();
            Config single;
            single.host = seed.host;
            single.port = seed.port;
            single.tls = config.tls;
            single.read_token = config.read_token;
            single.write_token = config.write_token;
            single.timeout = config.timeout;
            single.document_limit = config.document_limit;
            single.request_limit = config.request_limit;
            single.response_limit = config.response_limit;
            endpoints.emplace_back(single);
        }
    }
    Control control(const RequestOptions &request) const {
        if (request.timeout.count() < 0 || request.timeout.count() > 30000)
            invalid();
        return {Control::Clock::now() + (request.timeout.count()
                                             ? std::min(config.timeout, request.timeout)
                                             : config.timeout),
                request.cancellation};
    }
    Spec document(std::string_view method, std::string_view c, std::string_view d,
                  std::string_view body, const WriteOptions &options,
                  const Control &control) const {
        Spec s;
        s.method = method;
        s.write = true;
        s.path = docpath(c, d, true);
        s.collection = c;
        s.document = d;
        s.body = body;
        s.etag = options.etag;
        s.create_only = options.create_only;
        s.request_id = options.request_id;
        revision(s.etag);
        if (s.create_only && (method != "PUT" || !s.etag.empty()))
            invalid();
        if (method == "DELETE") {
            s.status = 204;
            s.maximum = 0;
        } else {
            s.maximum = config.document_limit;
            if (method == "PUT") {
                s.media = "application/yaml";
                s.alternate = 201;
                source_valid(s.body, std::min(config.document_limit, config.request_limit),
                             control);
            } else {
                s.media = "application/json";
                if (input_json(s.body, config.request_limit, control).fields.empty())
                    invalid();
            }
        }
        s.count = 1;
        return s;
    }
    Spec call(Operation op, std::string_view body, const CallOptions &options,
              const Control &control) const {
        Spec s;
        s.body = body;
        // Copy all mutable caller-owned options before decoding or any I/O.
        const CallOptions o = options;
        bool collection = false, job = false, changes = false, catalog = false;
        std::size_t maximum = std::min<std::size_t>(2 * 1024 * 1024, config.request_limit);
        switch (op) {
        case Operation::health:
            s.path = "/healthz";
            break;
        case Operation::ready:
            s.path = "/readyz";
            break;
        case Operation::stats:
            s.path = "/v1/stats";
            break;
        case Operation::metrics:
            s.path = "/metrics";
            s.maximum = max_document_bytes;
            break;
        case Operation::collections:
            s.path = "/v1/collections";
            break;
        case Operation::indexes:
            s.path = "/v1/indexes";
            break;
        case Operation::set_indexes:
            s.path = "/v1/indexes";
            s.method = "PUT";
            s.write = catalog = true;
            break;
        case Operation::start_index_build:
            s.path = "/v1/index-builds";
            s.method = "POST";
            s.write = catalog = true;
            s.status = 202;
            s.supported = false;
            break;
        case Operation::index_build:
            s.path = "/v1/index-builds";
            job = true;
            s.supported = false;
            break;
        case Operation::cancel_index_build:
            s.path = "/v1/index-builds";
            s.method = "DELETE";
            s.write = job = true;
            s.status = 202;
            s.supported = false;
            break;
        case Operation::query:
            s.path = "/v1/query/";
            s.method = "POST";
            collection = true;
            break;
        case Operation::aggregate:
            s.path = "/v1/aggregate/";
            s.method = "POST";
            collection = true;
            break;
        case Operation::search:
            s.path = "/v1/search/";
            s.method = "POST";
            collection = true;
            break;
        case Operation::transaction:
            s.path = "/v1/transactions";
            s.method = "POST";
            s.write = true;
            maximum = config.request_limit;
            break;
        case Operation::changes:
            s.path = "/v1/changes";
            changes = true;
            break;
        case Operation::cluster_status:
            s.path = "/v1/cluster/status";
            break;
        case Operation::cluster_leader:
            s.path = "/v1/cluster/leader";
            break;
        case Operation::replication_status:
            s.path = "/v1/replication/status";
            s.supported = false;
            break;
#define PHASE(name, route)                                                                         \
    case Operation::name:                                                                          \
        s.path = route;                                                                            \
        s.method = "POST";                                                                         \
        s.write = true;                                                                            \
        s.supported = false;                                                                       \
        break
            PHASE(replication_begin, "/v1/replication/begin");
            PHASE(replication_apply, "/v1/replication/apply");
            PHASE(replication_commit, "/v1/replication/commit");
            PHASE(replication_abort, "/v1/replication/abort");
            PHASE(follow_begin, "/v1/replication/follow/begin");
            PHASE(follow_apply, "/v1/replication/follow/apply");
            PHASE(follow_commit, "/v1/replication/follow/commit");
            PHASE(follow_abort, "/v1/replication/follow/abort");
#undef PHASE
        default:
            invalid();
        }
        revision(o.revision);
        if (!o.request_id.empty() && (!s.write || !nonzero(o.request_id)))
            invalid();
        s.request_id = o.request_id;
        if (collection) {
            id(o.collection);
            s.path += o.collection;
        } else if (!o.collection.empty())
            invalid();
        if (job) {
            if (s.write && o.job_id.empty())
                invalid();
            if (!o.job_id.empty()) {
                if (!hex(o.job_id, 32))
                    invalid();
                s.path += "/" + o.job_id;
            }
        } else if (!o.job_id.empty())
            invalid();
        if (changes) {
            if (o.limit < 1 || o.limit > 100 ||
                (!o.after.empty() && !token(o.after, config.cluster_id)))
                invalid();
            if (!o.after.empty())
                s.path += "?after=" + o.after + "&limit=" + std::to_string(o.limit);
        } else if (!o.after.empty() || o.limit != 100)
            invalid();
        if (catalog)
            s.etag = o.revision;
        else {
            if (s.write && !o.revision.empty())
                invalid();
            s.expected_revision = o.revision;
        }
        if (s.method == "POST" || s.method == "PUT") {
            auto v = input_json(s.body, maximum, control);
            s.media = "application/json";
            if (s.supported && s.write) {
                try {
                    if (catalog) {
                        v.keys({"indexes"});
                        v.get("indexes").list();
                        s.count = 1;
                    } else {
                        v.keys({"operations", "revision"});
                        if (auto p = v.optional("revision")) {
                            require(hex(p->str(), 16));
                        }
                        auto &ops = v.get("operations").list();
                        require(!ops.empty() && ops.size() <= 128);
                        std::set<std::pair<std::string, std::string>> identities;
                        for (const auto &item : ops) {
                            control.check();
                            item.keys({"collection", "document", "put", "patch", "delete", "etag",
                                       "create_only"});
                            auto c = item.get("collection").str(), d = item.get("document").str();
                            docpath(c, d, true);
                            require(identities.emplace(c, d).second);
                            auto put = item.optional("put"), patch = item.optional("patch"),
                                 del = item.optional("delete");
                            require(static_cast<int>(put != nullptr) +
                                        static_cast<int>(patch != nullptr) +
                                        static_cast<int>(del != nullptr) ==
                                    1);
                            if (put)
                                source_valid(put->str(), config.document_limit, control);
                            if (patch)
                                require(patch->type == Json::object && !patch->fields.empty());
                            if (del)
                                require(del->boolean_value());
                            if (auto tag = item.optional("etag"))
                                require(hex(tag->str(), 16));
                            if (auto create = item.optional("create_only"))
                                require(!create->boolean_value() ||
                                        (put && !item.optional("etag")));
                        }
                        s.count = ops.size();
                    }
                } catch (const Error &e) {
                    if (e.kind() == ErrorKind::protocol)
                        invalid();
                    throw;
                }
            }
        } else if (!s.body.empty())
            invalid();
        return s;
    }
    PreparedMutation freeze(Spec s, const Control &control) const {
        if (!s.write)
            invalid();
        if (s.request_id.empty())
            s.request_id = generate_id();
        if (!nonzero(s.request_id))
            invalid();
        if (s.create_only)
            s.headers = "If-None-Match: *\r\n";
        else if (!s.etag.empty())
            s.headers = "If-Match: \"" + s.etag + "\"\r\n";
        s.headers += "X-Yamora-Request-Id: " + s.request_id + "\r\n";
        control.check();
        return PreparedMutation(
            std::make_shared<const PreparedMutation::Data>(std::move(s), config.cluster_id));
    }
    std::optional<std::size_t> discover(const Control &control, unsigned &attempts) {
        std::size_t start;
        std::uint64_t observed;
        {
            std::lock_guard<std::mutex> lock(mutex);
            start = cached < 0 ? cursor : static_cast<std::size_t>(cached);
            observed = generation;
        }
        for (std::size_t offset = 0; offset < endpoints.size() && attempts < 32; ++offset) {
            control.check();
            auto index = (start + offset) % endpoints.size();
            bool dispatched = false;
            try {
                ++attempts;
                auto r = endpoints[index].exchange(
                    "GET", "/v1/cluster/status", {}, {}, {}, false, 4096, 200, 0, {},
                    control.budget(config.attempt_timeout, endpoints.size() - offset + 2),
                    dispatched);
                auto v = public_json(r, control);
                require(v.get("node").uint() == static_cast<unsigned>(config.seeds[index].node) &&
                        v.get("leader").uint() == static_cast<unsigned>(config.seeds[index].node) &&
                        v.get("voters").uint() == static_cast<unsigned>(config.voters) &&
                        v.get("term").uint() > 0 && v.get("role").str() == "leader" &&
                        !v.get("failed").boolean_value() &&
                        v.get("applied").uint() <= v.get("committed").uint() &&
                        v.get("committed").uint() <= v.get("last").uint());
                if (attempts >= 32)
                    return {};
                ++attempts;
                auto f = endpoints[index].exchange(
                    "GET", "/v1/changes", {}, {}, {}, false, 4096, 200, 0, {},
                    control.budget(config.attempt_timeout, endpoints.size() - offset + 1),
                    dispatched);
                feed(public_json(f, control), config.cluster_id, true);
                control.check();
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    if (generation == observed) {
                        cached = static_cast<int>(index);
                        cursor = (index + 1) % endpoints.size();
                        ++generation;
                    }
                }
                return index;
            } catch (const Error &e) {
                if (e.kind() == ErrorKind::cancelled ||
                    (e.kind() == ErrorKind::http && (e.status() == 401 || e.status() == 403)))
                    throw;
                control.check();
            }
        }
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (generation == observed) {
                cached = -1;
                cursor = (start + 1) % endpoints.size();
                ++generation;
            }
        }
        return {};
    }
    Response run(const Spec &s, const Control &control,
                 const PreparedMutation *mutation = nullptr) {
        // Construct the exception and its owned envelope BEFORE dispatch. Catch
        // bad_alloc too: wrapping an allocation failure must not allocate again.
        std::optional<UncertainWriteError> recovery;
        if (mutation)
            recovery.emplace(*mutation);
        // Each terminal failure linearizes at this acquire load. A sibling
        // execute() can publish ambiguity after this call starts, including
        // while this call is still discovering and has not dispatched.
        auto uncertain_now = [&] {
            return mutation && mutation->data_->uncertain.load(std::memory_order_acquire);
        };
        auto mark = [&] {
            if (mutation) {
                mutation->data_->uncertain.store(true, std::memory_order_release);
            }
        };
        try {
            unsigned attempts = 0;
            auto delay = std::chrono::milliseconds(25);
            Error last(ErrorKind::http, "yamora: no verified cluster route", 503);
            for (;;) {
                control.check();
                if (attempts >= 32)
                    throw last;
                auto route = discover(control, attempts);
                if (route && attempts < 32) {
                    ++attempts;
                    bool dispatched = false;
                    try {
                        auto r = endpoints[*route].exchange(
                            s.method, s.path, s.body, s.media, s.headers, s.write, s.maximum,
                            s.status, s.alternate, s.expected_revision,
                            control.budget(config.attempt_timeout, endpoints.size() > 1 ? 2 : 1),
                            dispatched);
                        if (mutation) {
                            require(s.supported);
                            receipt(r, s, control);
                        } else if (s.media != "raw-yaml" && s.path != "/metrics") {
                            auto v = public_json(r, control);
                            if (s.path.rfind("/v1/changes", 0) == 0)
                                feed(v, config.cluster_id, s.path == "/v1/changes");
                        }
                        control.check();
                        return r;
                    } catch (const Error &e) {
                        bool definite = e.kind() == ErrorKind::http && e.status() >= 400 &&
                                        e.status() <= 499 && e.status() != 408;
                        if (dispatched && !definite)
                            mark();
                        control.check();
                        if (!(e.kind() == ErrorKind::transport || e.kind() == ErrorKind::deadline ||
                              (e.kind() == ErrorKind::http && e.status() == 503)))
                            throw;
                        last = e;
                        {
                            std::lock_guard<std::mutex> lock(mutex);
                            if (cached == static_cast<int>(*route)) {
                                cached = -1;
                                cursor = (*route + 1) % endpoints.size();
                                ++generation;
                            }
                        }
                    } catch (...) {
                        if (dispatched)
                            mark();
                        throw;
                    }
                }
                control.pause(delay);
                delay = std::min(delay * 2, std::chrono::milliseconds(500));
            }
        } catch (const Error &e) {
            if (uncertain_now()) {
                recovery->failure(e.kind(), e.status());
                throw *recovery;
            }
            throw;
        } catch (...) {
            if (uncertain_now()) {
                recovery->failure(ErrorKind::allocation, 0);
                throw *recovery;
            }
            throw;
        }
    }
};
ClusterClient::ClusterClient(const ClusterConfig &config) : impl_(std::make_shared<Impl>(config)) {}
PreparedMutation ClusterClient::prepare_put(std::string_view c, std::string_view d,
                                            std::string_view body, const WriteOptions &o) const {
    auto control = impl_->control({});
    return impl_->freeze(impl_->document("PUT", c, d, body, o, control), control);
}
PreparedMutation ClusterClient::prepare_patch(std::string_view c, std::string_view d,
                                              std::string_view body, const WriteOptions &o) const {
    auto control = impl_->control({});
    return impl_->freeze(impl_->document("PATCH", c, d, body, o, control), control);
}
PreparedMutation ClusterClient::prepare_erase(std::string_view c, std::string_view d,
                                              const WriteOptions &o) const {
    auto control = impl_->control({});
    return impl_->freeze(impl_->document("DELETE", c, d, {}, o, control), control);
}
PreparedMutation ClusterClient::prepare_call(Operation op, std::string_view body,
                                             const CallOptions &o) const {
    auto control = impl_->control({});
    auto s = impl_->call(op, body, o, control);
    if (!s.supported)
        invalid();
    return impl_->freeze(std::move(s), control);
}
Response ClusterClient::execute(const PreparedMutation &mutation,
                                const RequestOptions &request) const {
    auto control = impl_->control(request);
    const auto &s = mutation.data_->spec;
    if (mutation.data_->cluster_id != impl_->config.cluster_id)
        invalid();
    if (s.body.size() > impl_->config.request_limit ||
        (s.method == "PUT" && !s.collection.empty() &&
         s.body.size() > impl_->config.document_limit))
        invalid();
    return impl_->run(s, control, &mutation);
}
Response ClusterClient::put(std::string_view c, std::string_view d, std::string_view body,
                            const WriteOptions &o, const RequestOptions &request) const {
    auto control = impl_->control(request);
    auto m = impl_->freeze(impl_->document("PUT", c, d, body, o, control), control);
    return impl_->run(m.data_->spec, control, &m);
}
Response ClusterClient::patch(std::string_view c, std::string_view d, std::string_view body,
                              const WriteOptions &o, const RequestOptions &request) const {
    auto control = impl_->control(request);
    auto m = impl_->freeze(impl_->document("PATCH", c, d, body, o, control), control);
    return impl_->run(m.data_->spec, control, &m);
}
Response ClusterClient::erase(std::string_view c, std::string_view d, const WriteOptions &o,
                              const RequestOptions &request) const {
    auto control = impl_->control(request);
    auto m = impl_->freeze(impl_->document("DELETE", c, d, {}, o, control), control);
    return impl_->run(m.data_->spec, control, &m);
}
Response ClusterClient::call(Operation op, std::string_view body, const CallOptions &o,
                             const RequestOptions &request) const {
    auto control = impl_->control(request);
    auto s = impl_->call(op, body, o, control);
    // New daemon capabilities cannot extend this client's frozen profile.
    // Reject before discovery or a write that we cannot validate or recover.
    if (!s.supported)
        invalid();
    if (s.write) {
        auto m = impl_->freeze(std::move(s), control);
        return impl_->run(m.data_->spec, control, &m);
    }
    return impl_->run(s, control);
}
Document ClusterClient::get(std::string_view c, std::string_view d, std::string_view rev,
                            const RequestOptions &request) const {
    auto control = impl_->control(request);
    Spec s;
    s.path = docpath(c, d, false);
    s.media = "raw-yaml";
    s.expected_revision = rev;
    revision(s.expected_revision);
    s.maximum = impl_->config.document_limit;
    auto r = impl_->run(s, control);
    control.check();
    return {std::move(r.body), std::move(r.etag), std::move(r.revision)};
}
Response ClusterClient::documents(std::string_view c, int limit, std::string_view after,
                                  std::string_view rev, const RequestOptions &request) const {
    auto control = impl_->control(request);
    id(c);
    if (limit < 1 || limit > 1000)
        invalid();
    Spec s;
    s.path = "/v1/collections/" + std::string(c) + "/documents?limit=" + std::to_string(limit);
    if (!after.empty()) {
        id(after);
        s.path += "&after=" + std::string(after);
    }
    s.expected_revision = rev;
    revision(s.expected_revision);
    return impl_->run(s, control);
}
} // namespace yamora
