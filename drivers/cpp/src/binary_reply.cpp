#include "binary_wire.hpp"
#include "json.hpp"

namespace yamora::binary_detail {
Reply response_metadata(std::string_view payload, unsigned schema) {
  require(payload.size() >= 4 && payload.size() <= max_metadata &&
          integer(payload.substr(0, 2)) == schema && (schema == 1 || schema == 2));
  auto count = integer(payload.substr(2, 2));
  require(count >= 5 && count <= (schema == 2 ? 13U : 12U));
  std::array<std::optional<std::string_view>, 14> fields{};
  std::size_t pos = 4, previous = 0;
  for (std::size_t i = 0; i < count; ++i) {
    require(payload.size() - pos >= 4);
    auto id = integer(payload.substr(pos, 2)),
         length = integer(payload.substr(pos + 2, 2));
    pos += 4;
    require(id > previous && id <= (schema == 2 ? 13U : 12U) && length <= payload.size() - pos);
    fields[id] = payload.substr(pos, static_cast<std::size_t>(length));
    previous = static_cast<std::size_t>(id);
    pos += static_cast<std::size_t>(length);
  }
  require(pos == payload.size());
  auto value = [&](std::size_t id) {
    require(fields[id].has_value());
    return *fields[id];
  };
  auto num = [&](std::size_t id, std::size_t width) {
    auto bytes = value(id);
    require(bytes.size() == width);
    return integer(bytes);
  };
  auto text = [&](std::size_t id, std::size_t maximum) {
    auto bytes = value(id);
    require(!bytes.empty() && ascii(bytes, maximum));
    return std::string(bytes);
  };
  Reply result;
  auto &r = result.value;
  r.status = static_cast<int>(num(1, 2));
  r.content_type = text(2, 95);
  result.length = num(3, 8);
  r.representation_length = num(4, 8);
  r.revision = text(5, 16);
  require(r.status >= 200 && r.status <= 599 && hex(r.revision, 16) &&
          result.length <= max_document_bytes &&
          r.representation_length <= max_document_bytes);
  require(result.length == 0 || result.length == r.representation_length);
  require(r.status != 204 ||
          (result.length == 0 && r.representation_length == 0));
  require(r.status != 304 || result.length == 0);
  if (fields[6]) {
    auto tag = text(6, 18);
    require(tag.size() == 18 && tag.front() == '"' && tag.back() == '"' &&
            hex(std::string_view(tag).substr(1, 16), 16));
    r.etag = tag.substr(1, 16);
  }
  for (std::size_t id : {7U, 8U}) {
    if (!fields[id])
      continue;
    auto target = text(id, 128);
    require(name(target));
    (id == 7 ? r.collection : r.document) = std::move(target);
  }
  if (fields[9]) {
    auto n = num(9, 1);
    require(n >= 1 && n <= (schema == 2 ? 63U : 15U) && r.status == 405);
    r.allow = static_cast<std::uint8_t>(n);
  }
  if (fields[10]) {
    require(num(10, 1) == 1 && r.status == 401);
    r.authenticate = 1;
  }
  if (fields[11]) {
    require(r.status == 429 || r.status == 503);
    r.retry_after_seconds = static_cast<std::uint32_t>(num(11, 4));
  }
  if (fields[12]) {
    auto bytes = value(12);
    require(bytes.size() == 16 &&
            bytes.find_first_not_of('\0') != std::string_view::npos);
    std::string id;
    for (char b : bytes) {
      auto c = static_cast<unsigned char>(b);
      id += "0123456789abcdef"[c >> 4U];
      id += "0123456789abcdef"[c & 15U];
    }
    r.request_id = std::move(id);
  }
  if (schema == 2) {
    auto mode = num(13, 1);
    require(mode <= 1 && (!mode || (r.status == 200 && result.length == 0 && r.representation_length == 0)));
    result.streaming = mode == 1;
  }
  return result;
}
namespace {
std::string media(std::string_view value) {
  // Native metadata parameters are opaque printable ASCII after ';'.
  std::string result(value.substr(0, value.find(';')));
  for (auto &c : result)
    if (c >= 'A' && c <= 'Z')
      c = static_cast<char>(c + ('a' - 'A'));
  return result;
}
} // namespace
void correlate(const Reply &reply, BinaryMethod method,
               std::string_view collection, std::string_view document,
               const BinaryOptions &options) {
  const auto &r = reply.value;
  require(r.request_id == options.request_id &&
          (!r.collection || *r.collection == collection) &&
          (!r.document || *r.document == document));
  require(method == BinaryMethod::head || r.status == 304
              ? reply.length == 0
              : reply.length == r.representation_length);
  auto type = media(r.content_type);
  if (method == BinaryMethod::put || method == BinaryMethod::erase ||
      r.status >= 400)
    require(r.representation_length <= max_ack);
  if (r.status >= 400) {
    require(type == "application/json");
    return;
  }
  switch (method) {
  case BinaryMethod::get:
  case BinaryMethod::head:
    require((r.status == 200 || r.status == 304) && !r.etag.empty() &&
            r.collection && *r.collection == collection && r.document &&
            *r.document == document &&
            (type == "application/yaml" || type == "text/yaml"));
    if (r.status == 304)
      require(options.if_none_match &&
              (*options.if_none_match == "*" ||
               *options.if_none_match == "\"" + r.etag + "\""));
    break;
  case BinaryMethod::put:
    require((r.status == 200 || r.status == 201) &&
            type == "application/json" && !r.etag.empty() && reply.length > 0);
    if (options.if_match)
      require(r.status == 200);
    if (options.if_none_match && *options.if_none_match == "*")
      require(r.status == 201);
    break;
  case BinaryMethod::erase:
    require(r.status == 204 && reply.length == 0 &&
            r.representation_length == 0 && type == "application/json" &&
            r.etag.empty());
    break;
  }
}
void semantics(const Reply &reply, BinaryMethod method,
               std::string_view collection, std::string_view document,
               std::string_view source, const detail::Control &control) {
  const auto &r = reply.value;
  require(r.body.size() == reply.length);
  if (method == BinaryMethod::head || r.status == 204 || r.status == 304)
    return;
  if (r.status == 200 && method == BinaryMethod::get) {
    utf8(r.body, control);
    require(source_etag(r.body, control) == r.etag);
    return;
  }
  // Numeric views in Json borrow this bounded, still-live reply body.
  const auto json = detail::decode(r.body, control);
  require(json.type == detail::Json::object);
  if (r.status >= 400) {
    require(json.fields.size() == 1);
    const auto &code = json.get("error").str();
    require(!code.empty() && code.size() <= 128 &&
            std::all_of(code.begin(), code.end(), [](unsigned char c) {
              return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                     c == '_';
            }));
  } else {
    require(method == BinaryMethod::put && json.fields.size() == 5 &&
            json.get("status").str() == "stored" &&
            json.get("collection").str() == collection &&
            json.get("document").str() == document &&
            json.get("revision").str() == r.revision &&
            json.get("etag").str() == r.etag &&
            source_etag(source, control) == r.etag);
  }
  control.check();
}
} // namespace yamora::binary_detail
