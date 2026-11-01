#include "yamora/client.hpp"
#include <algorithm>
#include <cstdlib>
#include <future>
#include <iostream>
#include <iterator>
#include <sstream>
#include <thread>
#include <vector>

void fault_cancellation(std::shared_ptr<yamora::Cancellation>);
void fault_reset() noexcept;

namespace {
std::string env(const char *key, std::string fallback = {}) {
    auto p = std::getenv(key);
    return p ? p : fallback;
}
void ensure(bool b) {
    if (!b)
        throw std::runtime_error("probe assertion failed");
}
yamora::ClusterConfig configuration() {
    yamora::ClusterConfig c;
    c.cluster_id = env("CPP_CLUSTER_ID", std::string(32, 'c'));
    c.voters = std::stoi(env("CPP_VOTERS", "3"));
    c.timeout = std::chrono::milliseconds(std::stoi(env("CPP_TIMEOUT", "5000")));
    c.attempt_timeout = std::chrono::milliseconds(std::stoi(env("CPP_ATTEMPT_TIMEOUT", "1000")));
    c.response_limit = std::stoul(env("CPP_RESPONSE_LIMIT", "67108864"));
    c.read_token = env("CPP_READ_TOKEN", std::string(32, 'r'));
    c.write_token = env("CPP_WRITE_TOKEN", std::string(32, 'w'));
    auto tls = std::make_shared<yamora::TLS>();
    tls->ca_file = env("CPP_CA");
    tls->certificate_file = env("CPP_CERT");
    tls->private_key_file = env("CPP_KEY");
    c.tls = tls;
    if (env("CPP_NO_TLS") == "1")
        c.tls.reset();
    std::stringstream seeds(env("CPP_SEEDS"));
    std::string seed;
    while (std::getline(seeds, seed, ',')) {
        auto colon = seed.find(':');
        c.seeds.push_back({env("CPP_HOST", "127.0.0.1"), std::stoi(seed.substr(0, colon)),
                           std::stoi(seed.substr(colon + 1))});
    }
    return c;
}
yamora::Operation operation(std::string_view mode) {
#define OP(x)                                                                                      \
    if (mode == #x)                                                                                \
    return yamora::Operation::x
    OP(health);
    OP(ready);
    OP(stats);
    OP(metrics);
    OP(collections);
    OP(indexes);
    OP(set_indexes);
    OP(start_index_build);
    OP(index_build);
    OP(cancel_index_build);
    OP(query);
    OP(aggregate);
    OP(search);
    OP(transaction);
    OP(changes);
    OP(replication_status);
    OP(replication_begin);
    OP(replication_apply);
    OP(replication_commit);
    OP(replication_abort);
    OP(follow_begin);
    OP(follow_apply);
    OP(follow_commit);
    OP(follow_abort);
    OP(cluster_status);
    OP(cluster_leader);
#undef OP
    throw std::runtime_error("unknown operation");
}
void emit(const yamora::Response &r) {
    std::cout << r.status << '\n' << r.revision << '\n' << r.etag << '\n' << r.body;
}
} // namespace
int main(int argc, char **argv) {
    try {
        ensure(argc > 1);
        auto config = configuration();
        yamora::ClusterClient client(config);
        std::string mode = argv[1];
        std::string collection = argc > 2 ? argv[2] : "examples",
                    document = argc > 3 ? argv[3] : "one";
        if (mode == "config")
            return 0;
        const bool controlled = env("CPP_CONTROL") == "1";
        std::string input = (controlled || mode == "twice")
                                ? env("CPP_BODY")
                                : std::string(std::istreambuf_iterator<char>(std::cin), {});
        yamora::WriteOptions write{env("CPP_ETAG"), env("CPP_CREATE_ONLY") == "1",
                                   env("CPP_REQUEST_ID")};
        yamora::CallOptions options;
        options.request_id = write.request_id;
        options.revision = env("CPP_REVISION");
        options.job_id = env("CPP_JOB_ID");
        options.after = env("CPP_AFTER");
        options.limit = std::stoi(env("CPP_LIMIT", "100"));
        if (mode == "query" || mode == "aggregate" || mode == "search")
            options.collection = collection;
        auto cancel = std::make_shared<yamora::Cancellation>();
        fault_cancellation(cancel);
        yamora::RequestOptions request{
            cancel, std::chrono::milliseconds(std::stoi(env("CPP_REQUEST_TIMEOUT", "0")))};
        if (env("CPP_CANCELLED") == "1")
            cancel->cancel();
        auto action = [&]() -> yamora::Response {
            if (mode == "get") {
                auto d = client.get(collection, document, options.revision, request);
                return {200, std::move(d.source), std::move(d.revision), std::move(d.etag)};
            }
            if (mode == "put")
                return client.put(collection, document, input, write, request);
            if (mode == "patch")
                return client.patch(collection, document, input, write, request);
            if (mode == "erase")
                return client.erase(collection, document, write, request);
            if (mode == "documents")
                return client.documents(collection, std::stoi(env("CPP_LIMIT", "1000")),
                                        options.after, options.revision, request);
            if (mode == "shared-rejection") {
                auto mutation = client.prepare_put(collection, document, input, write);
                std::vector<std::future<std::pair<bool, int>>> calls;
                for (int i = 0; i < 2; ++i) {
                    calls.push_back(std::async(std::launch::async, [&, mutation] {
                        try {
                            client.execute(mutation);
                            throw std::runtime_error("shared fixture unexpectedly succeeded");
                        } catch (const yamora::UncertainWriteError &e) {
                            ensure(e.kind() == (e.status() == 0 ? yamora::ErrorKind::allocation
                                                                : yamora::ErrorKind::http));
                            ensure(e.request_id() == mutation.request_id() &&
                                   e.mutation().body() == mutation.body() &&
                                   e.mutation().path() == mutation.path() &&
                                   e.mutation().etag() == mutation.etag() &&
                                   e.mutation().create_only() == mutation.create_only() &&
                                   e.mutation().operation_count() == mutation.operation_count());
                            if (e.status() == 307)
                                std::cout << "AMBIGUOUS\n" << std::flush;
                            return std::make_pair(true, e.status());
                        } catch (const yamora::Error &e) {
                            return std::make_pair(false, e.status());
                        } catch (const std::bad_alloc &) {
                            return std::make_pair(false, 0);
                        }
                    }));
                }
                std::vector<int> statuses;
                for (auto &call : calls) {
                    auto result = call.get();
                    if (!result.first)
                        throw std::runtime_error(
                            "shared prepared mutation reported certainty after ambiguity");
                    statuses.push_back(result.second);
                }
                std::sort(statuses.begin(), statuses.end());
                std::vector<int> expected{307, std::stoi(env("CPP_SHARED_STATUS", "412"))};
                std::sort(expected.begin(), expected.end());
                ensure(statuses == expected);
                return {200, "shared recovery verified", std::string(16, '0'), {}};
            }
            if (mode == "prepared" || mode == "recover") {
                auto m = client.prepare_put(collection, document, input, write);
                const auto original = m.body(), original_id = m.request_id();
                input.assign("changed: true\n");
                write.etag = "ffffffffffffffff";
                write.request_id.assign(32, 'f');
                write.create_only = false;
                config.seeds.clear();
                config.read_token.assign(32, 'x');
                config.cluster_id.assign(32, 'f');
                ensure(m.body() == original && m.request_id() == original_id);
                if (mode == "prepared")
                    return client.execute(m, request);
                try {
                    client.execute(m, request);
                } catch (const yamora::UncertainWriteError &e) {
                    ensure(e.mutation().body() == original && e.request_id() == original_id);
                    return client.execute(e.mutation(), request);
                }
                throw std::runtime_error("recovery fixture did not cause uncertainty");
            }
            if (mode == "parallel" || mode == "isolation") {
                std::vector<std::future<yamora::Response>> calls;
                for (int i = 0; i < 6; ++i) {
                    auto local = write;
                    if (env("CPP_DISTINCT") == "1")
                        local.request_id = std::string(31, 'a') + static_cast<char>('1' + i);
                    calls.push_back(std::async(std::launch::async, [&, local, i] {
                        yamora::RequestOptions r = i == 0 ? request : yamora::RequestOptions{};
                        return client.patch(collection, document, input, local, r);
                    }));
                }
                yamora::Response r;
                for (std::size_t i = 0; i < calls.size(); ++i) {
                    try {
                        auto result = calls[i].get();
                        if (env("CPP_DISTINCT") != "1" && mode != "isolation" && i > 0)
                            ensure(r.body == result.body && r.revision == result.revision);
                        r = std::move(result);
                    } catch (const yamora::UncertainWriteError &e) {
                        if (!(mode == "isolation" && i == 0 &&
                              e.kind() == yamora::ErrorKind::cancelled))
                            throw;
                    }
                }
                return r;
            }
            if (mode == "twice") {
                auto r = client.call(yamora::Operation::health);
                std::cout << "FIRST\n" << std::flush;
                std::string line;
                std::getline(std::cin, line);
                return client.call(yamora::Operation::health);
            }
            return client.call(operation(mode), input, options, request);
        };
        if (controlled) {
            auto future = std::async(std::launch::async, action);
            std::cout << "START\n" << std::flush;
            std::string command;
            std::getline(std::cin, command);
            if (env("CPP_MUTATE") == "1") {
                input.assign("changed: true\n");
                write.etag.assign(16, 'f');
                write.request_id.assign(32, 'f');
                write.create_only = false;
                std::cout << "MUTATED\n" << std::flush;
            } else
                cancel->cancel();
            emit(future.get());
        } else
            emit(action());
        return 0;
    } catch (const yamora::UncertainWriteError &e) {
        fault_reset();
        std::cerr << static_cast<int>(e.kind()) << ' ' << e.status() << " 1\n" << e.what() << '\n';
        const auto &m = e.mutation();
        std::cout << m.request_id() << '\n'
                  << m.method() << '\n'
                  << m.path() << '\n'
                  << m.etag() << '\n'
                  << m.create_only() << '\n'
                  << m.operation_count() << '\n'
                  << m.body();
        return 2;
    } catch (const yamora::Error &e) {
        fault_reset();
        std::cerr << static_cast<int>(e.kind()) << ' ' << e.status() << ' ' << e.uncertain() << '\n'
                  << e.what() << '\n';
        return 2;
    } catch (const std::exception &e) {
        fault_reset();
        std::cerr << e.what() << '\n';
        return 3;
    }
}
