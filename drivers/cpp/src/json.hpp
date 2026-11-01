#pragma once
#include "control.hpp"
#include <cstdint>
#include <limits>
#include <map>
#include <vector>

namespace yamora::detail {
[[noreturn]] inline void bad_json() {
    throw Error(ErrorKind::protocol, "yamora: invalid JSON schema or encoding");
}
inline void require(bool value) {
    if (!value)
        bad_json();
}
struct Json {
    enum Type { null, boolean, number, string, array, object } type = null;
    bool flag = false;
    std::string text;
    std::string_view numeric;
    std::vector<Json> items;
    std::map<std::string, Json> fields;
    const Json *optional(const char *key) const {
        require(type == object);
        auto it = fields.find(key);
        return it == fields.end() ? nullptr : &it->second;
    }
    const Json &get(const char *key) const {
        auto p = optional(key);
        require(p);
        return *p;
    }
    const std::string &str() const {
        require(type == string);
        return text;
    }
    bool boolean_value() const {
        require(type == boolean);
        return flag;
    }
    std::uint64_t uint() const {
        require(type == number && !numeric.empty());
        std::uint64_t value = 0;
        for (auto c : numeric) {
            require(c >= '0' && c <= '9');
            auto digit = static_cast<unsigned>(c - '0');
            require(value <= (std::numeric_limits<std::uint64_t>::max() - digit) / 10);
            value = value * 10 + digit;
        }
        return value;
    }
    const std::vector<Json> &list() const {
        require(type == array);
        return items;
    }
    void keys(std::initializer_list<std::string_view> allowed) const {
        require(type == object);
        for (const auto &field : fields)
            require(std::find(allowed.begin(), allowed.end(), field.first) != allowed.end());
    }
};
// Bounded syntax tree used only for validation. Numbers remain lexical views:
// no double conversion or reserialization can change application JSON bytes.
class JsonParser {
    std::string_view input;
    const Control &control;
    unsigned max_depth;
    std::size_t pos = 0, nodes = 0, next_check = 0;
    void checkpoint() {
        if (pos >= next_check) {
            control.check();
            next_check = pos + 1024;
        }
    }
    char peek() {
        checkpoint();
        return pos < input.size() ? input[pos] : '\0';
    }
    char take() {
        char c = peek();
        require(pos < input.size());
        ++pos;
        return c;
    }
    void ws() {
        while (peek() == ' ' || peek() == '\t' || peek() == '\n' || peek() == '\r')
            ++pos;
    }
    void literal(std::string_view word) {
        for (auto c : word)
            require(take() == c);
    }
    unsigned hex4() {
        unsigned value = 0;
        for (int i = 0; i < 4; ++i) {
            char c = take();
            unsigned d;
            if (c >= '0' && c <= '9')
                d = static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f')
                d = static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                d = static_cast<unsigned>(c - 'A' + 10);
            else
                bad_json();
            value = value * 16 + d;
        }
        return value;
    }
    static void encode(std::string &out, unsigned point) {
        if (point < 128)
            out += static_cast<char>(point);
        else if (point < 2048) {
            out += static_cast<char>(0xc0U | (point >> 6U));
            out += static_cast<char>(0x80U | (point & 63U));
        } else if (point < 65536) {
            out += static_cast<char>(0xe0U | (point >> 12U));
            out += static_cast<char>(0x80U | ((point >> 6U) & 63U));
            out += static_cast<char>(0x80U | (point & 63U));
        } else {
            out += static_cast<char>(0xf0U | (point >> 18U));
            out += static_cast<char>(0x80U | ((point >> 12U) & 63U));
            out += static_cast<char>(0x80U | ((point >> 6U) & 63U));
            out += static_cast<char>(0x80U | (point & 63U));
        }
    }
    std::string quoted() {
        require(take() == '"');
        std::string out;
        for (;;) {
            auto c = static_cast<unsigned char>(take());
            if (c == '"')
                return out;
            require(c >= 32);
            if (c == '\\') {
                char e = take();
                switch (e) {
                case '"':
                case '\\':
                case '/':
                    out += e;
                    break;
                case 'b':
                    out += '\b';
                    break;
                case 'f':
                    out += '\f';
                    break;
                case 'n':
                    out += '\n';
                    break;
                case 'r':
                    out += '\r';
                    break;
                case 't':
                    out += '\t';
                    break;
                case 'u': {
                    auto point = hex4();
                    if (point >= 0xd800 && point <= 0xdbff) {
                        require(take() == '\\' && take() == 'u');
                        auto second = hex4();
                        require(second >= 0xdc00 && second <= 0xdfff);
                        point = 0x10000 + ((point - 0xd800) << 10U) + second - 0xdc00;
                    } else
                        require(point < 0xdc00 || point > 0xdfff);
                    encode(out, point);
                    break;
                }
                default:
                    bad_json();
                }
            } else if (c < 128)
                out += static_cast<char>(c);
            else {
                unsigned count, point, minimum;
                if (c >= 0xc2 && c <= 0xdf) {
                    count = 1;
                    point = c & 31U;
                    minimum = 128;
                } else if (c >= 0xe0 && c <= 0xef) {
                    count = 2;
                    point = c & 15U;
                    minimum = 2048;
                } else if (c >= 0xf0 && c <= 0xf4) {
                    count = 3;
                    point = c & 7U;
                    minimum = 65536;
                } else
                    bad_json();
                out += static_cast<char>(c);
                for (unsigned i = 0; i < count; ++i) {
                    auto b = static_cast<unsigned char>(take());
                    require((b & 0xc0U) == 0x80U);
                    point = (point << 6U) | (b & 63U);
                    out += static_cast<char>(b);
                }
                require(point >= minimum && point <= 0x10ffff &&
                        (point < 0xd800 || point > 0xdfff));
            }
        }
    }
    void digits() {
        require(peek() >= '0' && peek() <= '9');
        do {
            ++pos;
        } while (peek() >= '0' && peek() <= '9');
    }
    Json value(unsigned depth) {
        require(depth <= max_depth && ++nodes <= 262144);
        ws();
        Json v;
        switch (peek()) {
        case '{':
            v.type = Json::object;
            ++pos;
            ws();
            if (peek() == '}') {
                ++pos;
                return v;
            }
            for (;;) {
                auto key = quoted();
                ws();
                require(take() == ':');
                auto child = value(depth + 1);
                require(v.fields.emplace(std::move(key), std::move(child)).second);
                ws();
                auto c = take();
                if (c == '}')
                    return v;
                require(c == ',');
                ws();
            }
        case '[':
            v.type = Json::array;
            ++pos;
            ws();
            if (peek() == ']') {
                ++pos;
                return v;
            }
            for (;;) {
                v.items.push_back(value(depth + 1));
                ws();
                auto c = take();
                if (c == ']')
                    return v;
                require(c == ',');
                ws();
            }
        case '"':
            v.type = Json::string;
            v.text = quoted();
            return v;
        case 't':
            literal("true");
            v.type = Json::boolean;
            v.flag = true;
            return v;
        case 'f':
            literal("false");
            v.type = Json::boolean;
            return v;
        case 'n':
            literal("null");
            return v;
        default: {
            v.type = Json::number;
            auto start = pos;
            if (peek() == '-')
                ++pos;
            if (peek() == '0')
                ++pos;
            else
                digits();
            if (peek() == '.') {
                ++pos;
                digits();
            }
            if (peek() == 'e' || peek() == 'E') {
                ++pos;
                if (peek() == '+' || peek() == '-')
                    ++pos;
                digits();
            }
            v.numeric = input.substr(start, pos - start);
            return v;
        }
        }
    }

  public:
    JsonParser(std::string_view bytes, const Control &op, unsigned depth_limit = 64)
        : input(bytes), control(op), max_depth(depth_limit) {}
    Json decode() {
        control.check();
        require(!input.empty() && input.size() <= max_response_bytes);
        auto v = value(0);
        ws();
        require(pos == input.size());
        control.check();
        return v;
    }
};
Json decode(std::string_view bytes, const Control &control);
} // namespace yamora::detail
