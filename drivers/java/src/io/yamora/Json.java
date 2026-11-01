package io.yamora;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Bounded JSON values. Numbers retain their original decimal token, never a double. */
public final class Json {
    public static final int MAX_BYTES = 64 * 1024 * 1024;
    public static final int MAX_DEPTH = 64;
    public static final int MAX_NODES = 100_000;

    private Json() {}

    /** Exact number token; conversion is an explicit application choice. */
    public record NumberValue(String text) {
        public NumberValue {
            Objects.requireNonNull(text);
            if (text.length() > 1024 || !text.matches("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")) {
                throw invalid();
            }
        }
        public long longValueExact() { return new BigDecimal(text).longValueExact(); }
        public BigInteger bigIntegerExact() { return new BigDecimal(text).toBigIntegerExact(); }
        public BigDecimal decimal() { return new BigDecimal(text); }
        @Override public String toString() { return text; }
    }

    /** Maps preserve authored key order, including compound sort priority. All containers are immutable. */
    public static Object parse(String source) {
        return parse(source, MAX_DEPTH);
    }

    private static Object parse(String source, int maxDepth) {
        Objects.requireNonNull(source);
        if (source.length() > MAX_BYTES) throw invalid();
        Parser parser = new Parser(source, maxDepth);
        Object value = parser.value(0);
        parser.space();
        if (parser.pos != source.length()) throw invalid();
        return value;
    }

    public static Map<String, Object> object(String source) {
        return object(source, MAX_DEPTH);
    }

    // Operation responses add query/facet containers around native depth64 values.
    static Map<String, Object> operationResponseObject(String source) {
        return object(source, 80);
    }

    private static Map<String, Object> object(String source, int maxDepth) {
        Object value = parse(source, maxDepth);
        if (!(value instanceof Map<?, ?>)) throw invalid();
        @SuppressWarnings("unchecked") Map<String, Object> map = (Map<String, Object>) value;
        return map;
    }

    /** Encodes parsed values, string-keyed maps, lists, and exact integral/decimal JDK types.
     * Float/Double and arbitrary Number implementations are intentionally rejected. */
    public static String stringify(Object value) {
        Writer writer = new Writer();
        writer.value(value, 0);
        return writer.out.toString();
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("yamora: invalid or over-budget JSON");
    }

    private static final class Parser {
        final String source;
        final int maxDepth;
        int pos;
        int nodes;
        Parser(String source, int maxDepth) { this.source = source; this.maxDepth = maxDepth; }
        void space() {
            while (pos < source.length() && " \t\r\n".indexOf(source.charAt(pos)) >= 0) pos++;
        }
        char take() {
            if (pos == source.length()) throw invalid();
            return source.charAt(pos++);
        }
        boolean consume(char ch) {
            if (pos < source.length() && source.charAt(pos) == ch) { pos++; return true; }
            return false;
        }
        Object value(int depth) {
            if (depth > maxDepth || ++nodes > MAX_NODES) throw invalid();
            space();
            if (pos == source.length()) throw invalid();
            char ch = source.charAt(pos);
            if (ch == '"') return string();
            if (ch == '{') {
                pos++;
                Map<String, Object> map = new LinkedHashMap<>();
                space();
                if (consume('}')) return Collections.unmodifiableMap(map);
                do {
                    space();
                    if (++nodes > MAX_NODES) throw invalid();
                    String key = string();
                    if (map.containsKey(key)) throw invalid();
                    space();
                    if (!consume(':')) throw invalid();
                    map.put(key, value(depth + 1));
                    space();
                    if (consume('}')) return Collections.unmodifiableMap(map);
                } while (consume(','));
                throw invalid();
            }
            if (ch == '[') {
                pos++;
                List<Object> list = new ArrayList<>();
                space();
                if (consume(']')) return Collections.unmodifiableList(list);
                do {
                    list.add(value(depth + 1));
                    space();
                    if (consume(']')) return Collections.unmodifiableList(list);
                } while (consume(','));
                throw invalid();
            }
            for (String literal : new String[]{"true", "false", "null"}) {
                if (source.startsWith(literal, pos)) {
                    pos += literal.length();
                    return literal.equals("null") ? null : Boolean.valueOf(literal);
                }
            }
            int start = pos;
            while (pos < source.length() && "-+0123456789.eE".indexOf(source.charAt(pos)) >= 0) {
                if (++pos - start > 1024) throw invalid();
            }
            return new NumberValue(source.substring(start, pos));
        }
        String string() {
            if (take() != '"') throw invalid();
            StringBuilder out = new StringBuilder();
            while (true) {
                char ch = take();
                if (ch == '"') { validUnicode(out); return out.toString(); }
                if (ch < 32) throw invalid();
                if (ch != '\\') { out.append(ch); continue; }
                char escape = take();
                switch (escape) {
                    case '"', '\\', '/' -> out.append(escape);
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'u' -> {
                        int code = 0;
                        for (int i = 0; i < 4; i++) {
                            char digit = take();
                            int hex = digit <= 127 ? Character.digit(digit, 16) : -1;
                            if (hex < 0) throw invalid();
                            code = code * 16 + hex;
                        }
                        out.append((char) code);
                    }
                    default -> throw invalid();
                }
            }
        }
    }

    private static void validUnicode(CharSequence value) {
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (Character.isHighSurrogate(ch)) {
                if (++i == value.length() || !Character.isLowSurrogate(value.charAt(i))) throw invalid();
            } else if (Character.isLowSurrogate(ch)) throw invalid();
        }
    }

    private static final class Writer {
        final StringBuilder out = new StringBuilder();
        int nodes;
        void append(String value) {
            if (value.length() > MAX_BYTES - out.length()) throw invalid();
            out.append(value);
        }
        void value(Object value, int depth) {
            if (depth > MAX_DEPTH || ++nodes > MAX_NODES) throw invalid();
            if (value == null) append("null");
            else if (value instanceof Boolean || value instanceof NumberValue || value instanceof Byte
                    || value instanceof Short || value instanceof Integer || value instanceof Long
                    || value instanceof BigInteger || value instanceof BigDecimal) {
                String token = value.toString();
                if (!(value instanceof Boolean)) new NumberValue(token);
                append(token);
            } else if (value instanceof String str) string(str);
            else if (value instanceof List<?> list) {
                if (list.size() > MAX_NODES) throw invalid();
                append("[");
                boolean first = true;
                for (Object entry : list) {
                    if (!first) append(",");
                    first = false;
                    value(entry, depth + 1);
                }
                append("]");
            } else if (value instanceof Map<?, ?> map) {
                if (map.size() > MAX_NODES) throw invalid();
                append("{");
                boolean first = true;
                for (Map.Entry<?, ?> entry : map.entrySet()) {
                    if (!(entry.getKey() instanceof String key) || ++nodes > MAX_NODES) throw invalid();
                    if (!first) append(",");
                    first = false;
                    string(key);
                    append(":");
                    value(entry.getValue(), depth + 1);
                }
                append("}");
            } else throw invalid();
        }
        void string(String value) {
            if (value.length() > MAX_BYTES) throw invalid();
            validUnicode(value);
            append("\"");
            for (int i = 0; i < value.length(); i++) {
                char ch = value.charAt(i);
                switch (ch) {
                    case '"' -> append("\\\"");
                    case '\\' -> append("\\\\");
                    case '\n' -> append("\\n");
                    case '\r' -> append("\\r");
                    case '\t' -> append("\\t");
                    default -> {
                        // LibYAML also recognizes NEL and Unicode line separators inside JSON strings.
                        if (ch < 32 || ch == 0x85 || ch == 0x2028 || ch == 0x2029) {
                            append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) ch));
                        } else append(String.valueOf(ch));
                    }
                }
            }
            append("\"");
        }
    }
}
