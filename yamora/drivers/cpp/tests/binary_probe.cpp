#include "yamora/binary.hpp"
#include <cstdlib>
#include <fstream>
#include <future>
#include <iostream>
#include <iterator>
#include <thread>

extern std::atomic<unsigned> binary_large_freezes;
extern std::atomic<bool> binary_fail_allocations;
extern std::atomic<unsigned> binary_failed_allocations;

namespace {
std::string env(const char *name, std::string fallback = {}) {
  const char *value = std::getenv(name);
  return value ? value : fallback;
}
std::string file(const std::string &path) {
  if (path.empty())
    return {};
  std::ifstream input(path, std::ios::binary);
  if (!input)
    throw std::runtime_error("fixture file missing");
  return {std::istreambuf_iterator<char>(input), {}};
}
void ensure(bool condition, const char *message) {
  if (!condition)
    throw std::runtime_error(message);
}
void print(const yamora::BinaryResponse &r) {
  std::cout << r.status << '\n'
            << r.revision << '\n'
            << r.etag << '\n'
            << r.representation_length << '\n'
            << r.request_id.value_or("") << '\n'
            << r.body;
}
yamora::BinaryConfig config(int port) {
  yamora::BinaryConfig c;
  c.host = env("B_HOST", "127.0.0.1");
  c.port = port;
  c.server_identity = env("B_IDENTITY", "127.0.0.1");
  c.ca_pem = file(env("B_CA"));
  c.client_certificate_pem = file(env("B_CERT"));
  c.client_private_key_pem = file(env("B_KEY"));
  c.max_frame_bytes =
      static_cast<std::size_t>(std::stoul(env("B_FRAME", "65536")));
  c.max_concurrent_calls =
      static_cast<std::size_t>(std::stoul(env("B_SLOTS", "4")));
  c.timeout = std::chrono::milliseconds(std::stoi(env("B_TIMEOUT", "5000")));
  return c;
}
yamora::BinaryOptions options() {
  yamora::BinaryOptions o;
  if (std::getenv("B_MATCH"))
    o.if_match = env("B_MATCH");
  if (std::getenv("B_NONE"))
    o.if_none_match = env("B_NONE");
  if (std::getenv("B_REQUEST_ID"))
    o.request_id = env("B_REQUEST_ID");
  return o;
}
template <class F> void invalid(F f) {
  try {
    f();
  } catch (const yamora::Error &e) {
    ensure(e.kind() == yamora::ErrorKind::invalid_argument,
           "wrong validation kind");
    return;
  }
  throw std::runtime_error("invalid input accepted");
}
void validation(const yamora::BinaryConfig &base) {
  for (auto host : {"localhost", "::1", "127.1", "127.00.0.1", "0177.0.0.1",
                    "0.0.0.0", "169.254.169.254", "8.8.8.8", "100.64.0.1",
                    "172.32.0.1", "127.0.0.1/path"})
    invalid([&] {
      auto c = base;
      c.host = host;
      yamora::BinaryClient client(c);
    });
  for (auto identity : {"", "bad..name", "-bad.test", "bad-.test", "bad.test.",
                        "https://x", "127.1", "127.0.0.1\n"})
    invalid([&] {
      auto c = base;
      c.server_identity = identity;
      yamora::BinaryClient client(c);
    });
  invalid([&] {
    auto c = base;
    c.server_identity = std::string("good\0bad", 8);
    yamora::BinaryClient client(c);
  });
  for (auto n : {0, 65536})
    invalid([&] {
      auto c = base;
      c.port = n;
      yamora::BinaryClient client(c);
    });
  for (auto n : {0, 5})
    invalid([&] {
      auto c = base;
      c.max_concurrent_calls = static_cast<std::size_t>(n);
      yamora::BinaryClient client(c);
    });
  for (auto n : {4095, 65537})
    invalid([&] {
      auto c = base;
      c.max_frame_bytes = static_cast<std::size_t>(n);
      yamora::BinaryClient client(c);
    });
  for (auto n : {0, -1, 30001})
    invalid([&] {
      auto c = base;
      c.timeout = std::chrono::milliseconds(n);
      yamora::BinaryClient client(c);
    });
  for (auto trust : {std::string(), base.ca_pem + "junk", "junk" + base.ca_pem,
                     base.ca_pem + "-----BEGIN CERTIFICATE-----\njunk"})
    invalid([&] {
      auto c = base;
      c.ca_pem = trust;
      yamora::BinaryClient client(c);
    });
  invalid([&] {
    auto c = base;
    c.client_private_key_pem.clear();
    yamora::BinaryClient client(c);
  });
  invalid([&] {
    auto c = base;
    c.client_private_key_pem += "junk";
    yamora::BinaryClient client(c);
  });
  yamora::BinaryClient client(base);
  for (auto id : {"", "Bad", "..", "a/b", "a%2fb", "a?x", "a\\b"})
    invalid([&] { client.get(id, "one"); });
  invalid([&] { client.get(std::string(129, 'a'), "one"); });
  for (auto id :
       {std::string(32, '0'), std::string(31, 'a'), std::string(32, 'A')})
    invalid([&] {
      yamora::BinaryOptions o;
      o.request_id = id;
      client.put("config", "item", "n: 1\n", {}, o);
    });
  for (auto token : {"x y", "x\n", "\xff"})
    invalid([&] { client.get("config", "item", token); });
  invalid([&] {
    client.put("config", "item",
               std::string(yamora::max_document_bytes + 1, 'x'));
  });
  invalid([&] { client.put("config", "item", "n: \xc0\x80"); });
  std::cout << "validation passed\n";
}
void concurrent(yamora::BinaryClient client, const std::string &token) {
  std::vector<std::shared_ptr<yamora::Cancellation>> cancels;
  std::vector<std::future<int>> workers;
  for (int i = 0; i < 4; ++i) {
    auto cancel = std::make_shared<yamora::Cancellation>();
    cancels.push_back(cancel);
    workers.push_back(
        std::async(std::launch::async, [client, cancel, i, &token] {
          try {
            return client
                .put("config", "parallel-" + std::to_string(i), "n: 1\n", token,
                     {}, {cancel, {}})
                .status;
          } catch (const yamora::BinaryUncertainWriteError &e) {
            ensure(i == 0 && e.kind() == yamora::ErrorKind::cancelled,
                   "sibling cancelled");
            return -1;
          }
        }));
  }
  std::string line;
  std::getline(std::cin, line); // fixture has observed four dispatches
  ensure(line == "waiters", "missing admission barrier");
  auto cancel = std::make_shared<yamora::Cancellation>();
  std::string source(yamora::max_document_bytes, 'x');
  auto waiter = std::async(std::launch::async, [&] {
    try {
      client.put("config", "waiting", source, token, {},
                 {cancel, std::chrono::milliseconds(1000)});
    } catch (const yamora::Error &e) {
      ensure(e.kind() == yamora::ErrorKind::cancelled && !e.uncertain(),
             "waiter cancellation");
      return;
    }
    throw std::runtime_error("waiter dispatched");
  });
  auto deadline = std::async(std::launch::async, [&] {
    try {
      client.put("config", "deadline", source, token, {},
                 {{}, std::chrono::milliseconds(70)});
    } catch (const yamora::Error &e) {
      ensure(e.kind() == yamora::ErrorKind::deadline && !e.uncertain(),
             "waiter deadline");
      return;
    }
    throw std::runtime_error("waiter dispatched");
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(30));
  cancel->cancel();
  waiter.get();
  deadline.get();
  cancels[0]->cancel();
  ensure(workers[0].get() == -1, "dispatched cancel not uncertain");
  std::cout << "WAITERS_CANCELLED " << binary_large_freezes.load() << '\n'
            << std::flush;
  std::getline(std::cin, line);
  ensure(line == "release", "missing release barrier");
  for (std::size_t i = 1; i < workers.size(); ++i)
    ensure(workers[i].get() == 201, "sibling socket affected");
  std::cout << "concurrency passed\n";
}
} // namespace
int main(int argc, char **argv) {
  try {
    ensure(argc >= 3, "port and mode required");
    auto c = config(std::stoi(argv[1]));
    std::string mode(argv[2]);
    if (mode == "validation") {
      validation(c);
      return 0;
    }
    yamora::BinaryClient client(c);
    if (mode == "freeze") {
      c.ca_pem.assign(c.ca_pem.size(), 'x');
      c.client_private_key_pem.assign(c.client_private_key_pem.size(), 'x');
      c.client_certificate_pem.clear();
      c.server_identity = "wrong.invalid";
      mode = "get";
    }
    auto token = env("B_TOKEN", (mode == "get" || mode == "head")
                                    ? std::string(32, 'r')
                                    : std::string(32, 'w'));
    if (mode == "concurrent") {
      concurrent(client, token);
      return 0;
    }
    if (mode == "native-parallel") {
      std::vector<std::future<void>> calls;
      for (int i = 0; i < 4; ++i)
        calls.push_back(std::async(std::launch::async, [client, i, token] {
          auto document = "parallel-" + std::to_string(i);
          const auto source =
              "# concurrent\r\nn: " + std::to_string(i) + "\r\n";
          ensure(client.put("config", document, source, token).status == 201,
                 "native concurrent write");
          ensure(client.get("config", document, std::string(32, 'r')).body ==
                     source,
                 "native concurrent source");
        }));
      for (auto &call : calls)
        call.get();
      std::cout << "native parallel passed\n";
      return 0;
    }
    const std::string collection = env("B_COLLECTION", "config"),
                      document = env("B_DOCUMENT", "item");
    auto o = options();
    auto cancel = std::make_shared<yamora::Cancellation>();
    yamora::RequestOptions request{cancel, std::chrono::milliseconds(std::stoi(
                                               env("B_REQUEST_TIMEOUT", "0")))};
    std::thread canceller;
    if (std::getenv("B_CANCEL_MS"))
      canceller = std::thread([cancel] {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(std::stoi(env("B_CANCEL_MS"))));
        cancel->cancel();
      });
    struct Join {
      std::thread &t;
      ~Join() {
        if (t.joinable())
          t.join();
      }
    } join{canceller};
    if (mode == "operation") {
      std::string source(std::istreambuf_iterator<char>(std::cin), {});
      print(client.operation(env("B_METHOD", "POST"), env("B_TARGET", "/v1/query/config"),
                             env("B_MEDIA", "application/json"), source, token, o, request));
    } else if (mode == "feed") {
      auto result = client.feed(env("B_TARGET"), [](std::string_view page) {
        std::cout << page << std::flush;
      }, token, o, request);
      std::cout << "CURSOR " << result.last_after << '\n';
    } else if (mode == "get")
      print(client.get(collection, document, token, o, request));
    else if (mode == "head")
      print(client.head(collection, document, token, o, request));
    else if (mode == "erase")
      print(client.erase(collection, document, token, o, request));
    else if (mode == "ownership") {
      auto source = file(env("B_SOURCE"));
      auto worker = std::async(std::launch::async, [&] {
        return client.put(collection, document, source, token, o, request);
      });
      std::string line;
      std::getline(std::cin, line);
      ensure(line == "mutate", "ownership barrier missing");
      source.assign(source.size(), 'x');
      token.assign(token.size(), 'z');
      o.request_id = std::string(32, 'f');
      o.if_none_match = "invalid";
      std::cout << "MUTATED\n" << std::flush;
      print(worker.get());
    } else {
      std::string source =
          mode == "recover"
              ? file(env("B_SOURCE"))
              : std::string(std::istreambuf_iterator<char>(std::cin), {});
      if (mode == "allocation") {
        try {
          client.put(collection, document, source, token, o, request);
          binary_fail_allocations.store(false);
          throw std::runtime_error("allocation fault did not occur");
        } catch (const yamora::BinaryUncertainWriteError &e) {
          // Keep failure active through both SDK catch/throw and caller catch.
          const bool held = binary_fail_allocations.load();
          binary_fail_allocations.store(false);
          ensure(held && binary_failed_allocations.load() > 0,
                 "allocator failure not held through propagation");
          const auto snapshot = e.envelope();
          const auto original = snapshot.options();
          const auto expected_kind = env("B_HOLD_ALLOC_FAILURE") == "error"
                                         ? yamora::ErrorKind::protocol
                                         : yamora::ErrorKind::allocation;
          ensure(e.kind() == expected_kind && e.uncertain() &&
                     snapshot.source() == source &&
                     snapshot.collection() == collection &&
                     snapshot.document() == document &&
                     snapshot.method() == yamora::BinaryMethod::put &&
                     original.if_none_match == o.if_none_match &&
                     original.if_match == o.if_match && original.request_id &&
                     (!o.request_id || original.request_id == o.request_id),
                 "allocation recovery snapshot changed");
          std::cout << "allocation snapshot preserved " << *original.request_id
                    << '\n';
        } catch (const std::bad_alloc &) {
          const bool held = binary_fail_allocations.load();
          binary_fail_allocations.store(false);
          ensure(held && binary_failed_allocations.load() > 0,
                 "allocator trace not armed");
          std::cout << "ALLOCATION_ENVELOPE_LOST\n";
        } catch (...) {
          binary_fail_allocations.store(false);
          throw;
        }
      } else if (mode == "recover") {
        try {
          client.put(collection, document, source, token, o, request);
          throw std::runtime_error("lost receipt accepted");
        } catch (const yamora::BinaryUncertainWriteError &e) {
          const auto envelope = e.envelope();
          ensure(envelope.source() == source &&
                     envelope.collection() == collection &&
                     envelope.document() == document &&
                     envelope.method() == yamora::BinaryMethod::put,
                 "wrong recovery snapshot");
          auto original = envelope.options();
          ensure(original.request_id.has_value(), "missing generated ID");
          if (o.request_id)
            ensure(original.request_id == o.request_id, "ID changed");
          source.assign(source.size(), 'x');
          o.request_id = std::string(32, 'f');
          o.if_none_match = "bad";
          auto copy = envelope.source();
          copy.assign(copy.size(), 'y');
          auto edited = envelope.options();
          edited.request_id = std::string(32, 'e');
          std::cout << "UNCERTAIN " << *original.request_id << '\n'
                    << std::flush;
          std::string line;
          std::getline(std::cin, line);
          ensure(line == "recover", "source verification barrier absent");
          print(client.execute(envelope, token, request));
        }
      } else
        print(client.put(collection, document, source, token, o, request));
    }
    return 0;
  } catch (const yamora::BinaryOperationError &e) {
    std::cerr << static_cast<int>(e.kind()) << ' ' << e.status() << ' ' << e.uncertain() << '\n';
    if (auto original = e.envelope()) {
      const auto expected = options();
      ensure(original->method() == env("B_METHOD", "POST") && original->target() == env("B_TARGET", "/v1/query/config") &&
                 original->content_type() == env("B_MEDIA", "application/json") &&
                 original->options().if_match == expected.if_match && original->options().if_none_match == expected.if_none_match,
             "operation envelope identity");
      std::cout << original->options().request_id.value_or("") << '\n' << original->source();
    } else if (argc > 2 && std::string(argv[2]) == "feed") std::cout << "CURSOR " << e.last_after() << '\n';
    return 2;
  } catch (const yamora::BinaryUnsupportedPeerError &e) {
    std::cerr << static_cast<int>(e.kind()) << " 0 0\nUNSUPPORTED\n";
    return 2;
  } catch (const yamora::BinaryUncertainWriteError &e) {
    std::cerr << static_cast<int>(e.kind()) << ' ' << e.status() << " 1\n"
              << e.what() << '\n';
    const auto o = e.envelope().options();
    std::cout << o.request_id.value_or("") << '\n' << e.envelope().source();
    return 2;
  } catch (const yamora::Error &e) {
    std::cerr << static_cast<int>(e.kind()) << ' ' << e.status() << " 0\n"
              << e.what() << '\n';
    return 2;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 3;
  }
}
