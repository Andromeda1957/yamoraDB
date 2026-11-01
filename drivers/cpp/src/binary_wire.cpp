#include "binary_wire.hpp"
#include <openssl/rand.h>

namespace yamora::binary_detail {
[[noreturn]] void invalid() {
  throw Error(ErrorKind::invalid_argument,
              "yamora: invalid binary configuration or input");
}
[[noreturn]] void protocol() {
  throw Error(ErrorKind::protocol, "yamora: invalid binary response");
}
[[noreturn]] void transport() {
  throw Error(ErrorKind::transport, "yamora: binary TLS or connection failure");
}
void require(bool condition) {
  if (!condition)
    protocol();
}
bool hex(std::string_view value, std::size_t size) {
  return value.size() == size &&
         std::all_of(value.begin(), value.end(), [](unsigned char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
         });
}
bool name(std::string_view value) {
  return !value.empty() && value.size() <= 128 &&
         std::all_of(value.begin(), value.end(), [](unsigned char c) {
           return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
         });
}
bool ascii(std::string_view value, std::size_t bound) {
  return value.size() <= bound &&
         std::all_of(value.begin(), value.end(),
                     [](unsigned char c) { return c >= 32 && c <= 126; });
}
void validate(BinaryMethod method, std::string_view collection,
              std::string_view document, std::string_view source,
              const BinaryOptions &options) {
  if (!name(collection) || !name(document) ||
      source.size() > max_document_bytes ||
      (method != BinaryMethod::put && !source.empty()))
    invalid();
  for (const auto *field : {&options.if_match, &options.if_none_match})
    if (*field && !ascii(**field, 31))
      invalid();
  if (options.request_id &&
      (!hex(*options.request_id, 32) ||
       options.request_id->find_first_not_of('0') == std::string::npos))
    invalid();
}
std::string freeze(std::string_view source, const detail::Control &control) {
  control.check();
  std::string owned;
  owned.reserve(source.size());
  for (std::size_t i = 0; i < source.size(); i += 4096) {
    control.check();
    owned.append(source.substr(i, 4096));
  }
  control.check();
  return owned;
}
void utf8(std::string_view source, const detail::Control &control) {
  std::size_t i = 0, next = 0;
  while (i < source.size()) {
    if (i >= next) {
      control.check();
      next = i + 1024;
    }
    unsigned c = static_cast<unsigned char>(source[i++]);
    if (c < 128)
      continue;
    unsigned count = 0, minimum = 0, point = 0;
    if (c >= 0xc2 && c <= 0xdf) {
      count = 1;
      minimum = 128;
      point = c & 31U;
    } else if (c >= 0xe0 && c <= 0xef) {
      count = 2;
      minimum = 2048;
      point = c & 15U;
    } else if (c >= 0xf0 && c <= 0xf4) {
      count = 3;
      minimum = 65536;
      point = c & 7U;
    } else
      protocol();
    require(count <= source.size() - i);
    for (unsigned j = 0; j < count; ++j) {
      unsigned b = static_cast<unsigned char>(source[i++]);
      require((b & 0xc0U) == 0x80U);
      point = (point << 6U) | (b & 63U);
    }
    require(point >= minimum && point <= 0x10ffff &&
            (point < 0xd800 || point > 0xdfff));
  }
  control.check();
}
std::string source_etag(std::string_view source,
                        const detail::Control &control) {
  std::uint64_t hash = UINT64_C(1469598103934665603);
  for (std::size_t i = 0; i < source.size(); i += 4096) {
    control.check();
    for (char c : source.substr(i, 4096))
      hash = (hash ^ static_cast<unsigned char>(c)) * UINT64_C(1099511628211);
  }
  std::string result(16, '0');
  for (std::size_t i = 16; i > 0; --i) {
    result[i - 1] = "0123456789abcdef"[hash & 15U];
    hash >>= 4U;
  }
  control.check();
  return result;
}
std::string random_id() {
  std::array<unsigned char, 16> bytes{};
  do {
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
      transport();
  } while (std::all_of(bytes.begin(), bytes.end(),
                       [](unsigned char c) { return c == 0; }));
  std::string result;
  for (auto c : bytes) {
    result += "0123456789abcdef"[c >> 4U];
    result += "0123456789abcdef"[c & 15U];
  }
  return result;
}
std::uint64_t integer(std::string_view bytes) {
  require(bytes.size() <= 8);
  std::uint64_t value = 0;
  for (char c : bytes)
    value = (value << 8U) | static_cast<unsigned char>(c);
  return value;
}
std::string number(std::uint64_t value, std::size_t width) {
  std::string result(width, '\0');
  for (std::size_t i = width; i > 0; --i) {
    result[i - 1] = static_cast<char>(value & 255U);
    value >>= 8U;
  }
  return result;
}
std::string request_metadata(BinaryMethod method, std::string_view collection,
                             std::string_view document, std::size_t length,
                             const BinaryOptions &options,
                             std::string_view bearer, unsigned timeout_ms) {
  std::string fields;
  unsigned count = 0;
  auto add = [&](unsigned id, std::string_view value) {
    fields += number(id, 2);
    fields += number(value.size(), 2);
    fields += value;
    ++count;
  };
  add(1, number(static_cast<unsigned>(method), 1));
  add(2, "/v1/collections/" + std::string(collection) + "/documents/" +
             std::string(document));
  add(3, method == BinaryMethod::put ? "application/yaml" : "");
  add(4, number(length, 8));
  if (!bearer.empty())
    add(5, "Bearer " + std::string(bearer));
  if (options.if_match)
    add(6, *options.if_match);
  if (options.if_none_match)
    add(7, *options.if_none_match);
  if (options.request_id) {
    std::string bytes;
    auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    for (std::size_t i = 0; i < 32; i += 2)
      bytes += static_cast<char>(digit((*options.request_id)[i]) * 16 +
                                 digit((*options.request_id)[i + 1]));
    add(8, bytes);
  }
  add(9, number(timeout_ms, 4));
  return number(1, 2) + number(count, 2) + fields;
}
std::string header(Kind kind, std::uint32_t stream, std::size_t length) {
  return std::string("YMBF\1", 5) + static_cast<char>(kind) + number(0, 2) +
         number(stream, 4) + number(length, 4);
}
FrameHeader decode_header(std::string_view bytes, std::size_t cap) {
  require(bytes.size() == 16 &&
          bytes.substr(0, 5) == std::string_view("YMBF\1", 5) &&
          integer(bytes.substr(6, 2)) == 0);
  auto kind = static_cast<Kind>(static_cast<unsigned char>(bytes[5]));
  auto stream = static_cast<std::uint32_t>(integer(bytes.substr(8, 4)));
  auto length = static_cast<std::uint32_t>(integer(bytes.substr(12, 4)));
  require(kind >= hello && kind <= goaway && length <= cap);
  bool connection =
      kind == hello || kind == ping || kind == pong || kind == goaway;
  require(connection ? stream == 0 : stream == 1);
  if (kind == hello)
    require(length == 12);
  if (kind == ping || kind == pong)
    require(length == 8);
  if (kind == end || kind == cancel || kind == goaway)
    require(length == 0);
  if (kind == error)
    require(length == 4);
  if (kind == request || kind == response)
    require(length >= 1 && length <= max_metadata);
  if (kind == data)
    require(length != 0);
  return {kind, stream, length};
}
std::size_t negotiate(std::string_view bytes, std::size_t cap) {
  require(bytes.size() == 12 && integer(bytes.substr(0, 2)) == 1 &&
          integer(bytes.substr(2, 2)) >= 1);
  auto frame = integer(bytes.substr(4, 4));
  auto streams = integer(bytes.substr(8, 4));
  require(frame >= 4096 && frame <= 65536 && streams >= 1 && streams <= 128);
  return std::min(cap, static_cast<std::size_t>(frame));
}
} // namespace yamora::binary_detail
