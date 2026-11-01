#include "yamora/client.hpp"
#include <cstdlib>
#include <future>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {
std::string env(const char *name, std::string fallback = {}) {
    const char *value = std::getenv(name);
    return value ? value : fallback;
}
void ensure(bool value) {
    if (!value)
        throw std::runtime_error("test assertion failed");
}
template <class F> void rejected(F fn) {
    try {
        fn();
    } catch (const yamora::Error &e) {
        ensure(e.kind() == yamora::ErrorKind::invalid_argument);
        return;
    }
    throw std::runtime_error("invalid input accepted");
}
void validation() {
    yamora::Config c;
    for (const auto &host :
         {"localhost", "http://127.0.0.1", "127.0.0.1/path", "127.0.0.1?x", "::1", "[::1]",
          "0.0.0.0", "8.8.8.8", "169.254.169.254", "100.64.0.1", "172.32.0.1", "192.0.2.1", "127.1",
          "0177.0.0.1", "127.0.0.1\r\nx: y"}) {
        rejected([&] {
            auto bad = c;
            bad.host = host;
            yamora::Client client(bad);
        });
    }
    rejected([&] {
        auto bad = c;
        bad.host = std::string("127.0.0.1\0suffix", 16);
        yamora::Client client(bad);
    });
    for (auto port : {-1, 0, 65536})
        rejected([&] {
            auto bad = c;
            bad.port = port;
            yamora::Client client(bad);
        });
    for (auto timeout : {-1, 0, 30001})
        rejected([&] {
            auto bad = c;
            bad.timeout = std::chrono::milliseconds(timeout);
            yamora::Client client(bad);
        });
    for (const auto &token :
         {std::string(31, 'a'), std::string(513, 'a'), std::string(32, ' '),
          std::string(31, 'a') + "\n", std::string(31, 'a') + '\0', std::string(32, '\xff')})
        for (bool write : {false, true})
            rejected([&] {
                auto bad = c;
                (write ? bad.write_token : bad.read_token) = token;
                yamora::Client client(bad);
            });
    for (const auto &host :
         {"127.0.0.1", "127.12.34.56", "10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1"}) {
        auto valid = c;
        valid.host = host;
        yamora::Client client(valid);
    }
    yamora::Client client(c);
    for (const auto &id : {"", ".", "..", "a/b", "A", "a%2fb", "a?x=y", "a\\b", "a\nx: y"}) {
        rejected([&] { client.get(id, "ok"); });
        rejected([&] { client.get("ok", id); });
    }
    rejected([&] { client.get(std::string(129, 'a'), "ok"); });
    rejected([&] { client.get("ok", "ok", "BAD"); });
    for (auto body : {std::string(), std::string("a: \xc0\x80"), std::string("a: \xed\xa0\x80"),
                      std::string("a: \xf4\x90\x80\x80"), std::string("a: \0", 4)})
        rejected([&] { client.put("ok", "ok", body); });
    rejected([&] { client.put("ok", "ok", std::string(yamora::max_document_bytes + 1, 'a')); });
    rejected([&] { client.patch("ok", "ok", "{}", {"", true, ""}); });
    rejected([&] { client.put("ok", "ok", "a: b\n", {"0123456789abcdef", true, ""}); });
    rejected([&] { client.put("ok", "ok", "a: b\n", {"", false, std::string(32, '0')}); });
    rejected([&] { client.erase("ok", "ok", {"*", false, ""}); });
    rejected([&] { client.patch("ok", "ok", "{\"x\":\"\xc2\x85\"}"); });
    rejected([&] { client.call(yamora::Operation::query, "{}"); });
    rejected([&] { client.call(yamora::Operation::health, "{}"); });
    rejected([&] {
        yamora::CallOptions opts;
        opts.request_id = std::string(32, 'a');
        client.call(yamora::Operation::health, {}, opts);
    });
    rejected([&] {
        yamora::CallOptions opts;
        opts.after = "../";
        client.call(yamora::Operation::changes, {}, opts);
    });
    rejected([&] {
        yamora::CallOptions opts;
        opts.limit = 101;
        client.call(yamora::Operation::changes, {}, opts);
    });
    rejected([&] {
        yamora::CallOptions opts;
        opts.job_id = "../";
        client.call(yamora::Operation::index_build, {}, opts);
    });
    rejected([&] { client.call(yamora::Operation::cancel_index_build); });
    rejected([&] { client.call(static_cast<yamora::Operation>(999)); });
    rejected([&] { client.documents("ok", 0); });
    rejected([&] { client.documents("ok", 1001); });
    rejected([&] {
        auto bad = c;
        bad.response_limit = yamora::max_response_bytes + 1;
        yamora::Client unused(bad);
    });
    rejected([&] {
        auto bad = c;
        bad.request_limit = 0;
        yamora::Client unused(bad);
    });
    rejected([&] {
        auto bad = c;
        bad.request_limit = 64;
        yamora::Client small(bad);
        small.patch("ok", "ok", std::string(65, 'a'));
    });
    rejected([&] {
        yamora::CallOptions opts;
        opts.collection = "ok";
        client.call(yamora::Operation::query, std::string(2 * 1024 * 1024 + 1, 'a'), opts);
    });
    rejected([&] {
        auto bad = c;
        auto tls = std::make_shared<yamora::TLS>();
        tls->certificate_file = "unpaired";
        bad.tls = tls;
        yamora::Client unused(bad);
    });
    std::cout << "validation passed\n";
}
} // namespace
int main(int argc, char **argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "validation") {
            validation();
            return 0;
        }
        if (argc < 4)
            throw std::runtime_error("host port operation required");
        yamora::Config config;
        config.host = argv[1];
        config.port = std::stoi(argv[2]);
        config.read_token = env("CPP_READ_TOKEN", std::string(32, 'r'));
        config.write_token = env("CPP_WRITE_TOKEN", std::string(32, 'w'));
        config.timeout = std::chrono::milliseconds(std::stoi(env("CPP_TIMEOUT", "5000")));
        config.response_limit =
            std::stoul(env("CPP_RESPONSE_LIMIT", std::to_string(yamora::max_response_bytes)));
        if (!env("CPP_TLS").empty()) {
            auto tls = std::make_shared<yamora::TLS>();
            tls->ca_file = env("CPP_CA");
            tls->certificate_file = env("CPP_CERT");
            tls->private_key_file = env("CPP_KEY");
            config.tls = tls;
        }
        yamora::Client client(config);
        std::string mode(argv[3]);
        std::string collection = argc > 4 ? argv[4] : "examples",
                    document = argc > 5 ? argv[5] : "one";
        std::string input((std::istreambuf_iterator<char>(std::cin)),
                          std::istreambuf_iterator<char>());
        yamora::WriteOptions write;
        write.etag = env("CPP_ETAG");
        write.create_only = !env("CPP_CREATE_ONLY").empty();
        write.request_id = env("CPP_REQUEST_ID");
        yamora::Response result;
        if (mode == "parallel") {
            std::vector<std::future<yamora::Response>> calls;
            for (int i = 0; i < 4; ++i)
                calls.push_back(std::async(std::launch::async, [client] {
                    return client.call(yamora::Operation::ready);
                }));
            for (auto &call : calls)
                result = call.get();
        } else if (mode == "replication-source") {
            result = client.require_replication_source();
        } else if (mode == "get") {
            auto doc = client.get(collection, document, env("CPP_REVISION"));
            result = {200, doc.source, doc.revision, doc.etag};
        } else if (mode == "put")
            result = client.put(collection, document, input, write);
        else if (mode == "patch")
            result = client.patch(collection, document, input, write);
        else if (mode == "erase")
            result = client.erase(collection, document, write);
        else if (mode == "documents")
            result = client.documents(collection, std::stoi(env("CPP_LIMIT", "1000")),
                                      env("CPP_AFTER"), env("CPP_REVISION"));
        else {
            const std::vector<std::pair<std::string, yamora::Operation>> operations = {
#define OP(name) {#name, yamora::Operation::name}
                OP(health),
                OP(ready),
                OP(stats),
                OP(metrics),
                OP(collections),
                OP(indexes),
                OP(set_indexes),
                OP(start_index_build),
                OP(index_build),
                OP(cancel_index_build),
                OP(query),
                OP(aggregate),
                OP(search),
                OP(transaction),
                OP(changes),
                OP(replication_status),
                OP(replication_begin),
                OP(replication_apply),
                OP(replication_commit),
                OP(replication_abort),
                OP(follow_begin),
                OP(follow_apply),
                OP(follow_commit),
                OP(follow_abort),
                OP(cluster_leader),
                OP(cluster_status)
#undef OP
            };
            bool found = false;
            for (const auto &item : operations)
                if (item.first == mode) {
                    yamora::CallOptions opts;
                    if (mode == "query" || mode == "aggregate" || mode == "search")
                        opts.collection = collection;
                    opts.job_id = env("CPP_JOB_ID");
                    opts.after = env("CPP_AFTER");
                    opts.revision = env("CPP_REVISION");
                    opts.request_id = env("CPP_REQUEST_ID");
                    opts.limit = std::stoi(env("CPP_LIMIT", "100"));
                    result = client.call(item.second, input, opts);
                    found = true;
                    break;
                }
            if (!found)
                throw std::runtime_error("unknown operation");
        }
        std::cout << result.status << '\n'
                  << result.revision << '\n'
                  << result.etag << '\n'
                  << result.body;
        return 0;
    } catch (const yamora::Error &e) {
        std::cerr << static_cast<int>(e.kind()) << ' ' << e.status() << ' ' << e.uncertain() << '\n'
                  << e.what() << '\n';
        return 2;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 3;
    }
}
