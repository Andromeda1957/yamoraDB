#pragma once
#include "control.hpp"
#include "yamora/binary.hpp"
#include <array>

namespace yamora::binary_detail {
inline constexpr std::string_view alpn = "yamora-binary/1";
inline constexpr std::size_t max_metadata = 2048, max_ack = 4096;
[[noreturn]] void invalid();
[[noreturn]] void protocol();
[[noreturn]] void transport();
void require(bool condition);
bool hex(std::string_view value, std::size_t size);
bool name(std::string_view value);
bool ascii(std::string_view value, std::size_t bound);
void validate(BinaryMethod method, std::string_view collection,
              std::string_view document, std::string_view source,
              const BinaryOptions &options);
void utf8(std::string_view source, const detail::Control &control);
std::string freeze(std::string_view source, const detail::Control &control);
std::string source_etag(std::string_view source,
                        const detail::Control &control);
std::string random_id();
std::uint64_t integer(std::string_view bytes);
std::string number(std::uint64_t value, std::size_t width);
std::string request_metadata(BinaryMethod method, std::string_view collection,
                             std::string_view document, std::size_t length,
                             const BinaryOptions &options,
                             std::string_view bearer, unsigned timeout_ms);
enum Kind : unsigned char {
  hello = 1,
  request = 2,
  response = 3,
  data = 4,
  end = 5,
  cancel = 6,
  error = 7,
  ping = 8,
  pong = 9,
  goaway = 10
};
struct FrameHeader {
  Kind kind;
  std::uint32_t stream, length;
};
std::string header(Kind kind, std::uint32_t stream, std::size_t length);
FrameHeader decode_header(std::string_view bytes, std::size_t cap);
std::size_t negotiate(std::string_view bytes, std::size_t cap);
struct Reply {
  BinaryResponse value;
  std::uint64_t length = 0;
  bool streaming = false;
};
Reply response_metadata(std::string_view payload, unsigned schema = 1);
void correlate(const Reply &reply, BinaryMethod method,
               std::string_view collection, std::string_view document,
               const BinaryOptions &options);
void semantics(const Reply &reply, BinaryMethod method,
               std::string_view collection, std::string_view document,
               std::string_view source, const detail::Control &control);
} // namespace yamora::binary_detail
