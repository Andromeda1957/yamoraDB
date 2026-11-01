#include "json.hpp"
namespace yamora::detail {
Json decode(std::string_view bytes, const Control &control) {
    return JsonParser(bytes, control).decode();
}
} // namespace yamora::detail
