// Persistent public-SDK adapter for ADAPTER_HTTP_REPLICA_V2.md. No HTTP or
// retry implementation belongs here; ClusterClient owns routing and retries.
#include "yamora/client.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <fcntl.h>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <type_traits>
#include <unistd.h>
#include <vector>

#ifdef YAMORA_HTTP_REPLICA_SELF_TEST
#include <cstdlib>
#include <new>
namespace {
bool fail_allocations = false;
long long allocation_countdown = -1;
} // namespace
void *operator new(std::size_t n) {
  if (allocation_countdown == 0)
    fail_allocations = true;
  else if (allocation_countdown > 0)
    --allocation_countdown;
  if (fail_allocations)
    throw std::bad_alloc();
  if (auto p = std::malloc(n ? n : 1))
    return p;
  throw std::bad_alloc();
}
void *operator new[](std::size_t n) { return ::operator new(n); }
void operator delete(void *p) noexcept { std::free(p); }
void operator delete[](void *p) noexcept { std::free(p); }
void operator delete(void *p, std::size_t) noexcept { std::free(p); }
void operator delete[](void *p, std::size_t) noexcept { std::free(p); }
#endif

namespace {
constexpr std::size_t line_limit = 16384, file_limit = 131072;
constexpr std::string_view command_schema = "yamora-http-replica-command/2";
using Clock = std::chrono::steady_clock;
struct Invalid {};
void require(bool value) {
  if (!value)
    throw Invalid{};
}

bool utf8(std::string_view s) {
  for (std::size_t i = 0; i < s.size();) {
    unsigned c = static_cast<unsigned char>(s[i++]);
    if (c < 128)
      continue;
    unsigned n, minimum;
    if (c >= 0xc2 && c <= 0xdf) {
      n = 1;
      minimum = 128;
      c &= 31;
    } else if (c >= 0xe0 && c <= 0xef) {
      n = 2;
      minimum = 2048;
      c &= 15;
    } else if (c >= 0xf0 && c <= 0xf4) {
      n = 3;
      minimum = 65536;
      c &= 7;
    } else
      return false;
    if (s.size() - i < n)
      return false;
    for (unsigned j = 0; j < n; ++j) {
      unsigned b = static_cast<unsigned char>(s[i++]);
      if ((b & 192) != 128)
        return false;
      c = (c << 6) | (b & 63);
    }
    if (c < minimum || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff))
      return false;
  }
  return true;
}

// Adapter-local JSON only. SDK internals are deliberately not dependencies.
struct Json {
  enum Kind { null, boolean, number, string, object, array } kind = null;
  std::string value;
  std::map<std::string, Json> members;
  std::vector<Json> items;
  const Json &at(const char *key) const {
    require(kind == object);
    auto it = members.find(key);
    require(it != members.end());
    return it->second;
  }
  const std::string &str() const {
    require(kind == string);
    return value;
  }
  int integer() const {
    require(kind == number);
    int result = 0;
    const auto parsed =
        std::from_chars(value.data(), value.data() + value.size(), result);
    require(parsed.ec == std::errc{} &&
            parsed.ptr == value.data() + value.size());
    return result;
  }
  bool is_null() const { return kind == null; }
  void keys(std::initializer_list<const char *> expected) const {
    require(kind == object && members.size() == expected.size());
    for (const auto key : expected)
      (void)at(key);
  }
};
class Parser {
  std::string_view input;
  std::size_t pos = 0;
  void whitespace() {
    while (pos < input.size() && (input[pos] == ' ' || input[pos] == '\t' ||
                                  input[pos] == '\r' || input[pos] == '\n'))
      ++pos;
  }
  bool take(char c) {
    if (pos < input.size() && input[pos] == c) {
      ++pos;
      return true;
    }
    return false;
  }
  unsigned hex4() {
    unsigned v = 0;
    for (unsigned i = 0; i < 4; ++i) {
      require(pos < input.size());
      char c = input[pos++];
      unsigned n = c >= '0' && c <= '9'   ? static_cast<unsigned>(c - '0')
                   : c >= 'a' && c <= 'f' ? static_cast<unsigned>(c - 'a' + 10)
                   : c >= 'A' && c <= 'F' ? static_cast<unsigned>(c - 'A' + 10)
                                          : 16;
      require(n < 16);
      v = v * 16 + n;
    }
    return v;
  }
  std::string text() {
    require(take('"'));
    std::string result;
    while (pos < input.size()) {
      unsigned char c = static_cast<unsigned char>(input[pos++]);
      if (c == '"')
        return result;
      require(c >= 32);
      if (c != '\\') {
        result += static_cast<char>(c);
        continue;
      }
      require(pos < input.size());
      char e = input[pos++];
      switch (e) {
      case '"':
      case '\\':
      case '/':
        result += e;
        break;
      case 'b':
        result += '\b';
        break;
      case 'f':
        result += '\f';
        break;
      case 'n':
        result += '\n';
        break;
      case 'r':
        result += '\r';
        break;
      case 't':
        result += '\t';
        break;
      case 'u': {
        unsigned point = hex4();
        if (point >= 0xd800 && point <= 0xdbff) {
          require(take('\\') && take('u'));
          unsigned low = hex4();
          require(low >= 0xdc00 && low <= 0xdfff);
          point = 0x10000 + ((point - 0xd800) << 10) + low - 0xdc00;
        } else
          require(point < 0xdc00 || point > 0xdfff);
        if (point < 128)
          result += static_cast<char>(point);
        else if (point < 2048) {
          result += static_cast<char>(192 | (point >> 6));
          result += static_cast<char>(128 | (point & 63));
        } else if (point < 65536) {
          result += static_cast<char>(224 | (point >> 12));
          result += static_cast<char>(128 | ((point >> 6) & 63));
          result += static_cast<char>(128 | (point & 63));
        } else {
          result += static_cast<char>(240 | (point >> 18));
          result += static_cast<char>(128 | ((point >> 12) & 63));
          result += static_cast<char>(128 | ((point >> 6) & 63));
          result += static_cast<char>(128 | (point & 63));
        }
        break;
      }
      default:
        throw Invalid{};
      }
    }
    throw Invalid{};
  }
  Json value(unsigned depth) {
    whitespace();
    require(pos < input.size());
    Json result;
    if (input[pos] == '{' || input[pos] == '[') {
      require(depth < 12);
      bool obj = take('{');
      if (!obj)
        require(take('['));
      result.kind = obj ? Json::object : Json::array;
      whitespace();
      char end = obj ? '}' : ']';
      if (take(end))
        return result;
      for (;;) {
        whitespace();
        if (obj) {
          auto key = text();
          whitespace();
          require(take(':'));
          auto child = value(depth + 1);
          require(
              result.members.emplace(std::move(key), std::move(child)).second);
        } else
          result.items.push_back(value(depth + 1));
        whitespace();
        if (take(end))
          return result;
        require(take(','));
      }
    }
    if (input[pos] == '"') {
      result.kind = Json::string;
      result.value = text();
      return result;
    }
    for (const auto literal : {"null", "true", "false"}) {
      std::string_view word(literal);
      if (input.substr(pos, word.size()) == word) {
        result.kind = word == "null" ? Json::null : Json::boolean;
        result.value = word;
        pos += word.size();
        return result;
      }
    }
    auto start = pos;
    take('-');
    auto digits = [&] {
      auto begin = pos;
      while (pos < input.size() && input[pos] >= '0' && input[pos] <= '9')
        ++pos;
      require(pos > begin);
    };
    if (!take('0'))
      digits();
    if (take('.'))
      digits();
    if (take('e') || take('E')) {
      if (!take('+'))
        take('-');
      digits();
    }
    result.kind = Json::number;
    result.value = input.substr(start, pos - start);
    // from_chars is locale independent, and refuses infinity/overflow.
    double finite = 0;
    auto parsed = std::from_chars(
        result.value.data(), result.value.data() + result.value.size(), finite);
    require(parsed.ec == std::errc{} && std::isfinite(finite));
    return result;
  }

public:
  explicit Parser(std::string_view bytes) : input(bytes) {}
  Json parse() {
    require(utf8(input));
    auto result = value(0);
    whitespace();
    require(pos == input.size());
    return result;
  }
};

struct Fd {
  int value = -1;
  explicit Fd(int n = -1) : value(n) { require(n >= 0); }
  Fd(const Fd &) = delete;
  Fd &operator=(const Fd &) = delete;
  Fd(Fd &&other) noexcept : value(std::exchange(other.value, -1)) {}
  ~Fd() {
    if (value >= 0)
      ::close(value);
  }
};
bool identifier(std::string_view s, std::size_t maximum = 128) {
  return !s.empty() && s.size() <= maximum &&
         std::all_of(s.begin(), s.end(), [](char c) {
           return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
         });
}
bool hex(std::string_view s, std::size_t n) {
  return s.size() == n && std::all_of(s.begin(), s.end(), [](char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
         });
}
bool identity(std::string_view s) {
  return hex(s, 32) && s.find_first_not_of('0') != s.npos;
}

// Every component is opened relative to an already-open directory. No realpath
// check followed by a symlink-following open, including for the root itself.
Fd walk(int root, std::string_view path, bool directory) {
  require(!path.empty() && path.size() <= 4096 && path.front() != '/');
  Fd current(::dup(root));
  std::size_t start = 0;
  for (;;) {
    auto slash = path.find('/', start);
    auto component = path.substr(start, slash == path.npos ? path.size() - start
                                                           : slash - start);
    require(!component.empty() && component != "." && component != ".." &&
            component.find('\0') == component.npos &&
            component.find('\\') == component.npos);
    std::string name(component);
    bool last = slash == path.npos;
    Fd next(::openat(current.value, name.c_str(),
                     O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK |
                         ((!last || directory) ? O_DIRECTORY : 0)));
    if (last)
      return next;
    std::swap(current.value, next.value);
    start = slash + 1;
  }
}
Fd session_root(const std::string &path) {
  require(path.size() > 1 && path.front() == '/');
  Fd slash(::open("/", O_RDONLY | O_CLOEXEC | O_DIRECTORY));
  auto root = walk(slash.value, std::string_view(path).substr(1), true);
  struct stat info{};
  require(::fstat(root.value, &info) == 0 && info.st_uid == ::geteuid() &&
          (info.st_mode & 0077) == 0);
  return root;
}
void regular(int fd, std::size_t maximum) {
  struct stat info{};
  require(::fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
          info.st_uid == ::geteuid() && info.st_size >= 0 &&
          static_cast<unsigned long long>(info.st_size) <= maximum &&
          (info.st_mode & 0022) == 0);
}
std::string read_file(int fd, std::size_t maximum) {
  regular(fd, maximum);
  std::string result;
  std::array<char, 4096> buffer{};
  for (;;) {
    auto n = ::read(fd, buffer.data(),
                    std::min(buffer.size(), maximum - result.size() + 1));
    if (n < 0 && errno == EINTR)
      continue;
    require(n >= 0);
    if (!n)
      return result;
    require(static_cast<std::size_t>(n) <= maximum - result.size());
    result.append(buffer.data(), static_cast<std::size_t>(n));
  }
}
std::string token_file(int root, const Json &path) {
  auto fd = walk(root, path.str(), false);
  // The raw-file budget includes a trailing LF/CRLF, before token trimming.
  auto result = read_file(fd.value, 512);
  if (!result.empty() && result.back() == '\n') {
    result.pop_back();
    if (!result.empty() && result.back() == '\r')
      result.pop_back();
  }
  require(!result.empty() &&
          std::all_of(result.begin(), result.end(),
                      [](unsigned char c) { return c >= 33 && c <= 126; }));
  return result;
}
struct Configuration {
  yamora::ClusterConfig sdk;
  std::vector<Fd> pem;
  explicit Configuration(int root) {
    auto fd = walk(root, "config.json", false);
    auto json = Parser(read_file(fd.value, line_limit)).parse();
    json.keys({"schema", "cluster_id", "voters", "seeds", "tls", "tokens",
               "timeout_ms", "attempt_timeout_ms"});
    require(json.at("schema").str() == "yamora-http-replica-config/2");
    sdk.cluster_id = json.at("cluster_id").str();
    require(identity(sdk.cluster_id));
    require(json.at("voters").integer() == 3 &&
            json.at("timeout_ms").integer() == 15000 &&
            json.at("attempt_timeout_ms").integer() == 3000);
    sdk.voters = 3;
    sdk.timeout = std::chrono::milliseconds(15000);
    sdk.attempt_timeout = std::chrono::milliseconds(3000);
    sdk.document_limit = sdk.request_limit = sdk.response_limit = file_limit;
    const auto &seeds = json.at("seeds");
    require(seeds.kind == Json::array && seeds.items.size() == 3);
    std::set<int> ports, nodes;
    for (const auto &seed : seeds.items) {
      seed.keys({"host", "port", "node"});
      int port = seed.at("port").integer(), node = seed.at("node").integer();
      require(seed.at("host").str() == "127.0.0.1" && port >= 1 &&
              port <= 65535 && port != 8000 && node >= 1 && node <= 3 &&
              ports.insert(port).second && nodes.insert(node).second);
      sdk.seeds.push_back({"127.0.0.1", port, node});
    }
    const auto &tls_json = json.at("tls");
    tls_json.keys({"ca_file", "cert_file", "key_file"});
    require(tls_json.at("ca_file").str() == "ca.pem" &&
            tls_json.at("cert_file").str() == "client.pem" &&
            tls_json.at("key_file").str() == "client.key");
    auto tls = std::make_shared<yamora::TLS>();
    for (const auto key : {"ca_file", "cert_file", "key_file"}) {
      auto file = walk(root, tls_json.at(key).str(), false);
      // Credential files have the 16 KiB config budget, not the source/body
      // budget. Read within that bound and reject empty PEM/key input.
      require(!read_file(file.value, line_limit).empty());
      require(::lseek(file.value, 0, SEEK_SET) == 0);
      // Pin the validated file even if a path is swapped during SDK setup.
      auto name = "/proc/self/fd/" + std::to_string(file.value);
      if (std::string_view(key) == "ca_file")
        tls->ca_file = name;
      else if (std::string_view(key) == "cert_file")
        tls->certificate_file = name;
      else
        tls->private_key_file = name;
      pem.push_back(std::move(file));
    }
    sdk.tls = tls;
    const auto &tokens = json.at("tokens");
    tokens.keys({"read_file", "write_file"});
    require(tokens.at("read_file").str() == "read.token" &&
            tokens.at("write_file").str() == "write.token");
    sdk.read_token = token_file(root, tokens.at("read_file"));
    sdk.write_token = token_file(root, tokens.at("write_file"));
  }
};

struct Command {
  std::string action, method, collection, document, source;
  yamora::WriteOptions options;
  unsigned handle = 0;
  explicit Command(const Json &j, unsigned seq, int root) {
    require(j.at("schema").str() == command_schema &&
            j.at("seq").integer() == static_cast<int>(seq) && seq <= 64);
    action = j.at("action").str();
    if (action == "close") {
      j.keys({"schema", "seq", "action"});
      return;
    }
    if (action == "recover") {
      j.keys({"schema", "seq", "action", "handle"});
      const auto &h = j.at("handle").str();
      require(h.size() >= 2 && h.size() <= 3 && h[0] == 'h' && h[1] != '0');
      auto parsed = std::from_chars(h.data() + 1, h.data() + h.size(), handle);
      require(parsed.ec == std::errc{} && parsed.ptr == h.data() + h.size() &&
              handle >= 1 && handle <= 16);
      return;
    }
    require(action == "call");
    j.keys({"schema", "seq", "action", "method", "collection", "document",
            "source_file", "request_id", "if_match", "if_none_match"});
    method = j.at("method").str();
    collection = j.at("collection").str();
    document = j.at("document").str();
    require((method == "GET" || method == "PUT" || method == "PATCH" ||
             method == "DELETE") &&
            identifier(collection) && identifier(document));
    require(method == "GET" || collection != "yamldb-system");
    const auto &id = j.at("request_id"), &match = j.at("if_match"),
               &none = j.at("if_none_match"), &file = j.at("source_file");
    if (!id.is_null()) {
      options.request_id = id.str();
      require(identity(options.request_id));
    }
    if (!match.is_null()) {
      auto &v = match.str();
      require(v.size() == 18 && v.front() == '"' && v.back() == '"' &&
              hex(std::string_view(v).substr(1, 16), 16));
      options.etag = v.substr(1, 16);
    }
    if (!none.is_null()) {
      require(none.str() == "*" && method == "PUT" && match.is_null());
      options.create_only = true;
    }
    if (method == "GET")
      require(id.is_null() && match.is_null() && none.is_null());
    if (method == "GET" || method == "DELETE") {
      require(file.is_null());
      return;
    }
    const auto &path = file.str();
    require(path.size() >= 11 && path.rfind("input/", 0) == 0 &&
            path.substr(path.size() - 4) == ".bin" &&
            identifier(std::string_view(path).substr(6, path.size() - 10), 64));
    auto fd = walk(root, path, false);
    source = read_file(fd.value, file_limit);
    require(!source.empty() && utf8(source));
    if (method == "PATCH") {
      auto patch = Parser(source).parse();
      patch.keys({"$inc"});
      const auto &inc = patch.at("$inc");
      inc.keys({"n"});
      require(inc.at("n").integer() == 1);
    }
  }
};

// Fixed-capacity serialization needs no heap allocation after an SDK error.
// In particular, storing an allocation-induced uncertain exception comes first.
class Output {
  std::array<char, line_limit> bytes{};
  std::size_t size = 0;

public:
  void raw(std::string_view s) {
    require(s.size() <= bytes.size() - size);
    std::copy(s.begin(), s.end(),
              bytes.begin() + static_cast<std::ptrdiff_t>(size));
    size += s.size();
  }
  void number(long long n) {
    std::array<char, 32> buffer{};
    auto p = std::to_chars(buffer.data(), buffer.data() + buffer.size(), n);
    require(p.ec == std::errc{});
    raw({buffer.data(), static_cast<std::size_t>(p.ptr - buffer.data())});
  }
  void quoted(std::string_view s) {
    raw("\"");
    constexpr char digits[] = "0123456789abcdef";
    for (char byte : s) {
      auto c = static_cast<unsigned char>(byte);
      if (c == '"')
        raw("\\\"");
      else if (c == '\\')
        raw("\\\\");
      else if (c < 32) {
        char escape[] = {'\\', 'u', '0', '0', digits[c >> 4], digits[c & 15]};
        raw({escape, sizeof escape});
      } else {
        char one = static_cast<char>(c);
        raw({&one, 1});
      }
    }
    raw("\"");
  }
  void nullable(const std::string *s) {
    if (s && !s->empty())
      quoted(*s);
    else
      raw("null");
  }
  void send() {
    raw("\n");
    std::size_t sent = 0;
    while (sent < size) {
      auto n = ::write(STDOUT_FILENO, bytes.data() + sent, size - sent);
      if (n < 0 && errno == EINTR)
        continue;
      require(n > 0);
      sent += static_cast<std::size_t>(n);
    }
  }
};
void write_file(int directory, const char *name, std::string_view data) {
  require(data.size() <= file_limit);
  Fd fd(::openat(directory, name,
                 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  std::size_t sent = 0;
  while (sent < data.size()) {
    auto n = ::write(fd.value, data.data() + sent, data.size() - sent);
    if (n < 0 && errno == EINTR)
      continue;
    require(n > 0);
    sent += static_cast<std::size_t>(n);
  }
}
const char *category(yamora::ErrorKind kind) {
  switch (kind) {
  case yamora::ErrorKind::transport:
    return "transport";
  case yamora::ErrorKind::protocol:
    return "protocol";
  case yamora::ErrorKind::http:
  case yamora::ErrorKind::schema_policy_replication_unsupported:
    return "status";
  case yamora::ErrorKind::cancelled:
    return "cancelled";
  case yamora::ErrorKind::deadline:
    return "deadline";
  // The v2 vocabulary has no allocation category. Preserve uncertainty and
  // its real envelope, without mislabeling allocation as a transport error.
  case yamora::ErrorKind::allocation:
    return nullptr;
  case yamora::ErrorKind::invalid_argument:
    return nullptr;
  }
  return nullptr;
}
struct Result {
  std::optional<yamora::Response> response;
  std::optional<yamora::Document> document;
  const yamora::UncertainWriteError *uncertain = nullptr;
  const char *outcome = "success", *kind = nullptr;
  int error_status = 0;
  long long elapsed = 0;
};
using Handles = std::array<std::optional<yamora::UncertainWriteError>, 16>;
static_assert(
    std::is_nothrow_copy_constructible<yamora::UncertainWriteError>::value,
    "retaining actual uncertainty must not allocate");

Result invoke(yamora::ClusterClient &client, Command &command, Handles &handles,
              unsigned &count) {
  Result r;
  auto start = Clock::now();
  try {
    yamora::RequestOptions request;
    request.timeout = std::chrono::milliseconds(15000);
    if (command.action == "recover")
      r.response.emplace(
          client.execute(handles[command.handle - 1]->mutation(), request));
    else if (command.method == "GET")
      r.document.emplace(
          client.get(command.collection, command.document, {}, request));
    else {
      auto mutation =
          command.method == "PUT"
              ? client.prepare_put(command.collection, command.document,
                                   command.source, command.options)
          : command.method == "PATCH"
              ? client.prepare_patch(command.collection, command.document,
                                     command.source, command.options)
              : client.prepare_erase(command.collection, command.document,
                                     command.options);
      auto used = std::chrono::duration_cast<std::chrono::milliseconds>(
          Clock::now() - start);
      require(used < request.timeout);
      request.timeout -= used;
      r.response.emplace(client.execute(mutation, request));
    }
  } catch (const yamora::UncertainWriteError &e) {
    // This copy precedes all output/file operations and does not allocate.
    if (command.action == "call")
      command.handle = ++count;
    handles[command.handle - 1].emplace(e);
    r.uncertain = &*handles[command.handle - 1];
    r.outcome = "uncertain";
    r.kind = category(e.kind());
    r.error_status = e.status();
  } catch (const yamora::Error &e) {
    r.kind = category(e.kind());
    require(r.kind != nullptr);
    r.outcome = r.kind;
    r.error_status = e.status();
  }
  r.elapsed =
      std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - start)
          .count();
  return r;
}
void observation(unsigned seq, const Command &c, const Result &r, int directory,
                 const char *relative) {
  Output out;
  const std::string *body = nullptr, *etag = nullptr, *revision = nullptr;
  int status = r.error_status;
  if (r.response) {
    body = &r.response->body;
    etag = &r.response->etag;
    revision = &r.response->revision;
    status = r.response->status;
  } else if (r.document) {
    body = &r.document->source;
    etag = &r.document->etag;
    revision = &r.document->revision;
  }
  if (body)
    write_file(directory, "body.bin", *body);
  if (r.uncertain)
    write_file(directory, "envelope.bin", r.uncertain->mutation().body());
  auto file = [&](const char *name) {
    // The only generated file names are fixed ASCII below this command.
    char path[64]{};
    auto n = std::snprintf(path, sizeof path, "%s/%s", relative, name);
    require(n > 0 && static_cast<std::size_t>(n) < sizeof path);
    out.quoted(path);
  };
  out.raw("{\"schema\":\"yamora-http-replica-observation/2\",\"seq\":");
  out.number(seq);
  out.raw(",\"action\":");
  out.quoted(c.action);
  out.raw(",\"outcome\":");
  out.quoted(r.outcome);
  out.raw(",\"error_kind\":");
  if (r.kind)
    out.quoted(r.kind);
  else
    out.raw("null");
  out.raw(",\"elapsed_ns\":");
  out.number(r.elapsed);
  out.raw(",\"api\":{\"status\":");
  if (status)
    out.number(status);
  else
    out.raw("null");
  out.raw(",\"body_file\":");
  if (body)
    file("body.bin");
  else
    out.raw("null");
  out.raw(",\"etag\":");
  out.nullable(etag);
  out.raw(",\"revision\":");
  out.nullable(revision);
  out.raw(",\"receipt\":null},\"sdk_request_id\":");
  if (r.uncertain)
    out.quoted(r.uncertain->request_id());
  else
    out.raw("null");
  out.raw(",\"envelope\":");
  if (r.uncertain) {
    const auto &m = r.uncertain->mutation();
    out.raw("{\"method\":");
    out.quoted(m.method());
    out.raw(",\"path\":");
    out.quoted(m.path());
    out.raw(",\"if_match\":");
    if (m.etag().empty())
      out.raw("null");
    else {
      // Quote the public, unquoted ETag without allocating a new string.
      out.raw("\"\\\"");
      out.raw(m.etag());
      out.raw("\\\"\"");
    }
    out.raw(",\"if_none_match\":");
    out.raw(m.create_only() ? "\"*\"" : "null");
    out.raw(",\"request_id\":");
    out.quoted(m.request_id());
    out.raw(",\"body_file\":");
    file("envelope.bin");
    out.raw("}");
  } else
    out.raw("null");
  out.raw(",\"recovery_mode\":");
  out.raw(c.handle ? "\"sdk-envelope\"" : "null");
  out.raw(",\"recovery_handle\":");
  if (c.handle) {
    char h[8]{};
    std::snprintf(h, sizeof h, "h%u", c.handle);
    out.quoted(h);
  } else
    out.raw("null");
  out.raw("}");
  out.send();
}
std::optional<std::string> line() {
  std::string result;
  while (result.size() < line_limit) {
    char c = 0;
    auto n = ::read(STDIN_FILENO, &c, 1);
    if (n < 0 && errno == EINTR)
      continue;
    require(n >= 0);
    if (!n) {
      require(result.empty());
      return {};
    }
    if (c == '\n')
      return result;
    // JSON files and escaped \\r remain valid; only raw JSONL-frame CR rejects.
    require(c != '\r');
    result += c;
    require(result.size() < line_limit);
  }
  throw Invalid{};
}
int run(int argc, char **argv) {
  require(argc == 5 && std::string_view(argv[1]) == "--config" &&
          std::string_view(argv[3]) == "--root");
  std::string root_path(argv[4]);
  require(std::string_view(argv[2]) == root_path + "/config.json");
  auto root = session_root(root_path);
  Configuration config(root.value);
  std::optional<yamora::ClusterClient> client;
  client.emplace(config.sdk);
  Handles handles;
  unsigned count = 0;
  for (unsigned seq = 1; seq <= 64; ++seq) {
    auto input = line();
    require(input.has_value());
    Command c(Parser(*input).parse(), seq, root.value);
    if (c.action == "close") {
      client.reset();
      for (auto &h : handles)
        h.reset();
      Result r;
      r.outcome = "closed";
      observation(seq, c, r, -1, "");
      return 0;
    }
    if (c.action == "recover")
      require(c.handle <= count && handles[c.handle - 1].has_value());
    // Reserve capacity before any call that could create uncertainty.
    else if (c.method != "GET")
      require(count < handles.size());
    char name[32]{};
    std::snprintf(name, sizeof name, "call-%06u", seq);
    auto directory = walk(root.value, name, true);
    struct stat info{};
    require(::fstat(directory.value, &info) == 0 &&
            info.st_uid == ::geteuid() && (info.st_mode & 0022) == 0);
    // Fixed output targets are validated before dispatch, too.
    for (const auto file : {"body.bin", "envelope.bin"}) {
      struct stat existing{};
      require(::fstatat(directory.value, file, &existing, AT_SYMLINK_NOFOLLOW) <
                  0 &&
              errno == ENOENT);
    }
#ifdef YAMORA_HTTP_REPLICA_SELF_TEST
    // Optional fault control for the compiled test binary only. Arm after
    // parsing/path validation; fail all new allocations inside the real SDK
    // call and its observation, then allow the next command to recover.
    if (seq == 1) {
      if (const char *fault = std::getenv("CPP_HTTP_ALLOCATION_AFTER")) {
        std::string_view digits(fault);
        auto p = std::from_chars(digits.data(), digits.data() + digits.size(),
                                 allocation_countdown);
        require(p.ec == std::errc{} && p.ptr == digits.data() + digits.size() &&
                allocation_countdown >= 0 && allocation_countdown <= 4096);
      }
    }
#endif
    auto result = invoke(*client, c, handles, count);
    observation(seq, c, result, directory.value, name);
#ifdef YAMORA_HTTP_REPLICA_SELF_TEST
    fail_allocations = false;
    allocation_countdown = -1;
#endif
  }
  throw Invalid{}; // A session without close is incomplete, even at the cap.
}

#ifdef YAMORA_HTTP_REPLICA_SELF_TEST
// Compile this same file with YAMORA_HTTP_REPLICA_SELF_TEST, then invoke
// --self-test ROOT with the usual owned fixture config/input/call directories.
// Network recovery is tested through the persistent protocol by the parent;
// this mode protects parser boundaries and allocation-free error reporting.
void self_test(const char *path) {
  for (const auto bad :
       {"{\"x\":1,\"x\":2}", "{\"x\":0,\"\\u0078\":1}", "[NaN]", "[Infinity]",
        "[1e999]", "[01]", "[true,]", "{}{}", "{\"x\":\"\\ud800\"}",
        "{\"x\":\"\\udc00\"}", "{\"x\":\"\n\"}"}) {
    bool rejected = false;
    try {
      (void)Parser(bad).parse();
    } catch (const Invalid &) {
      rejected = true;
    }
    require(rejected);
  }
  require(Parser("{\"x\":\"\\ud83d\\ude00\"}").parse().at("x").str() ==
          "\xf0\x9f\x98\x80");
  require(Parser("{\r\n\"x\":\"\\r\"}").parse().at("x").str() == "\r");
  for (unsigned depth : {12U, 13U}) {
    std::string text(depth, '[');
    text += '0';
    text += std::string(depth, ']');
    bool rejected = false;
    try {
      (void)Parser(text).parse();
    } catch (const Invalid &) {
      rejected = true;
    }
    require(rejected == (depth == 13));
  }
  require(!utf8("\xc0\x80") && !utf8("\xed\xa0\x80") &&
          !utf8("\xf4\x90\x80\x80"));
  auto root = session_root(path);
  for (const auto bad : {"../escape", "/absolute", "input/../config.json",
                         "input//a.bin", "input/./a.bin", "input/"}) {
    bool rejected = false;
    try {
      (void)walk(root.value, bad, false);
    } catch (const Invalid &) {
      rejected = true;
    }
    require(rejected);
  }
  Configuration config(root.value);
  yamora::ClusterClient client(config.sdk);
  auto command =
      Parser(
          R"({"schema":"yamora-http-replica-command/2","seq":1,"action":"call","method":"PATCH","collection":"manifests","document":"counter","source_file":"input/patch.bin","request_id":null,"if_match":"\"0123456789abcdef\"","if_none_match":null})")
          .parse();
  Command c(command, 1, root.value);
  auto mutation =
      client.prepare_patch(c.collection, c.document, c.source, c.options);
  require(identity(mutation.request_id()) &&
          mutation.etag() == "0123456789abcdef" &&
          mutation.body() == c.source && mutation.method() == "PATCH" &&
          mutation.path() == "/v1/collections/manifests/documents/counter");
  // Mutating caller primitives cannot affect the frozen SDK envelope.
  c.source = "changed";
  c.options.request_id = std::string(32, 'f');
  c.options.etag.clear();
  yamora::UncertainWriteError error(mutation);
  Handles handles;
  auto directory = walk(root.value, "call-000001", true);
  Result r;
  r.outcome = "uncertain";
  r.kind = "protocol";
  c.handle = 1;
  fail_allocations = true;
  handles[0].emplace(error);
  r.uncertain = &*handles[0];
  observation(1, c, r, directory.value, "call-000001");
  fail_allocations = false;
}
#endif
} // namespace

int main(int argc, char **argv) {
  try {
#ifdef YAMORA_HTTP_REPLICA_SELF_TEST
    if (argc == 2 && std::string_view(argv[1]) == "--validate-frame") {
      auto input = line();
      require(input.has_value());
      (void)Parser(*input).parse();
      return 0;
    }
    if (argc == 3 && std::string_view(argv[1]) == "--validate-config") {
      auto root = session_root(argv[2]);
      Configuration config(root.value);
      return 0;
    }
    if (argc == 3 && std::string_view(argv[1]) == "--self-test") {
      self_test(argv[2]);
      return 0;
    }
#endif
    return run(argc, argv);
  } catch (...) {
    // Never include exception text: SDK/PEM/peer errors can contain secrets.
    constexpr char diagnostic[] =
        "C++ HTTP replica adapter: invalid input or infrastructure failure\n";
    (void)::write(STDERR_FILENO, diagnostic, sizeof diagnostic - 1);
    return 2;
  }
}
