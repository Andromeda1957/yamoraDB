#include "compression.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_BITS 15
#define HASH_SIZE (1U << HASH_BITS)
#define WINDOW_SIZE 32768U
#define MAX_MATCH 258U
#define MIN_MATCH 3U
#define MAX_CHAIN 96U

typedef struct {
    unsigned char *output;
    size_t capacity;
    size_t used;
    uint64_t pending;
    unsigned int pending_bits;
} BitWriter;

static unsigned int reverse_bits(unsigned int value, unsigned int count)
{
    unsigned int reversed = 0;
    for (unsigned int index = 0; index < count; index++) {
        reversed = (reversed << 1) | (value & 1U);
        value >>= 1;
    }
    return reversed;
}

static bool write_bits(BitWriter *writer, unsigned int value, unsigned int count)
{
    writer->pending |= (uint64_t)value << writer->pending_bits;
    writer->pending_bits += count;
    while (writer->pending_bits >= 8) {
        if (writer->used == writer->capacity) {
            return false;
        }
        writer->output[writer->used++] = (unsigned char)(writer->pending & 0xffU);
        writer->pending >>= 8;
        writer->pending_bits -= 8;
    }
    return true;
}

static bool finish_bits(BitWriter *writer)
{
    if (writer->pending_bits == 0) {
        return true;
    }
    if (writer->used == writer->capacity) {
        return false;
    }
    writer->output[writer->used++] = (unsigned char)(writer->pending & 0xffU);
    writer->pending = 0;
    writer->pending_bits = 0;
    return true;
}

static bool write_fixed_symbol(BitWriter *writer, unsigned int symbol)
{
    unsigned int code;
    unsigned int bits;
    if (symbol <= 143) {
        code = 0x30U + symbol;
        bits = 8;
    } else if (symbol <= 255) {
        code = 0x190U + symbol - 144U;
        bits = 9;
    } else if (symbol <= 279) {
        code = symbol - 256U;
        bits = 7;
    } else if (symbol <= 287) {
        code = 0xc0U + symbol - 280U;
        bits = 8;
    } else {
        return false;
    }
    return write_bits(writer, reverse_bits(code, bits), bits);
}

static uint32_t hash_bytes(const unsigned char *input, size_t position)
{
    uint32_t value = (uint32_t)input[position] * UINT32_C(251);
    value ^= (uint32_t)input[position + 1] * UINT32_C(31);
    value ^= (uint32_t)input[position + 2];
    return (value * UINT32_C(2654435761)) >> (32 - HASH_BITS);
}

static void insert_position(
    const unsigned char *input,
    size_t input_length,
    size_t position,
    uint32_t head[HASH_SIZE],
    uint32_t *previous
)
{
    if (position + MIN_MATCH > input_length) {
        return;
    }
    uint32_t hash = hash_bytes(input, position);
    previous[position] = head[hash];
    head[hash] = (uint32_t)position + 1U;
}

static void find_match(
    const unsigned char *input,
    size_t input_length,
    size_t position,
    const uint32_t head[HASH_SIZE],
    const uint32_t *previous,
    size_t *best_length,
    size_t *best_distance
)
{
    *best_length = 0;
    *best_distance = 0;
    if (position + MIN_MATCH > input_length) {
        return;
    }
    size_t maximum = input_length - position;
    if (maximum > MAX_MATCH) {
        maximum = MAX_MATCH;
    }
    uint32_t link = head[hash_bytes(input, position)];
    unsigned int searched = 0;
    while (link != 0 && searched++ < MAX_CHAIN) {
        size_t candidate = (size_t)link - 1;
        size_t distance = position - candidate;
        if (distance == 0 || distance > WINDOW_SIZE) {
            if (distance > WINDOW_SIZE) {
                break;
            }
            link = previous[candidate];
            continue;
        }
        if (*best_length != 0 &&
            input[candidate + *best_length - 1] !=
                input[position + *best_length - 1]) {
            link = previous[candidate];
            continue;
        }
        size_t length = 0;
        while (length < maximum &&
               input[candidate + length] == input[position + length]) {
            length++;
        }
        if (length >= MIN_MATCH && length > *best_length) {
            *best_length = length;
            *best_distance = distance;
            if (length == maximum) {
                break;
            }
        }
        link = previous[candidate];
    }
}

static bool write_length(BitWriter *writer, size_t length)
{
    static const uint16_t bases[] = {
        3, 4, 5, 6, 7, 8, 9, 10,
        11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    };
    static const unsigned char extras[] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4,
        5, 5, 5, 5, 0,
    };
    for (size_t index = 0; index < sizeof(bases) / sizeof(bases[0]); index++) {
        size_t maximum = index + 1 < sizeof(bases) / sizeof(bases[0]) ?
            (size_t)bases[index + 1] - 1 : MAX_MATCH;
        if (length <= maximum) {
            return write_fixed_symbol(writer, 257U + (unsigned int)index) &&
                write_bits(
                    writer,
                    (unsigned int)(length - bases[index]),
                    extras[index]
                );
        }
    }
    return false;
}

static bool write_distance(BitWriter *writer, size_t distance)
{
    static const uint16_t bases[] = {
        1, 2, 3, 4, 5, 7, 9, 13,
        17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073,
        4097, 6145, 8193, 12289, 16385, 24577,
    };
    static const unsigned char extras[] = {
        0, 0, 0, 0, 1, 1, 2, 2,
        3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10,
        11, 11, 12, 12, 13, 13,
    };
    for (size_t index = 0; index < sizeof(bases) / sizeof(bases[0]); index++) {
        size_t maximum = index + 1 < sizeof(bases) / sizeof(bases[0]) ?
            (size_t)bases[index + 1] - 1 : WINDOW_SIZE;
        if (distance <= maximum) {
            return write_bits(
                    writer,
                    reverse_bits((unsigned int)index, 5),
                    5
                ) &&
                write_bits(
                    writer,
                    (unsigned int)(distance - bases[index]),
                    extras[index]
                );
        }
    }
    return false;
}

static uint32_t crc32_bytes(const unsigned char *input, size_t input_length)
{
    uint32_t crc = UINT32_C(0xffffffff);
    for (size_t index = 0; index < input_length; index++) {
        crc ^= input[index];
        for (unsigned int bit = 0; bit < 8; bit++) {
            uint32_t mask = 0U - (crc & 1U);
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & mask);
        }
    }
    return ~crc;
}

static void write_little_endian(unsigned char *output, uint32_t value)
{
    output[0] = (unsigned char)(value & 0xffU);
    output[1] = (unsigned char)((value >> 8) & 0xffU);
    output[2] = (unsigned char)((value >> 16) & 0xffU);
    output[3] = (unsigned char)((value >> 24) & 0xffU);
}

bool yamldb_gzip_compress(
    const unsigned char *input,
    size_t input_length,
    unsigned char **output,
    size_t *output_length,
    char *error,
    size_t error_length
)
{
    *output = NULL;
    *output_length = 0;
    if (input_length < 1024) {
        return true;
    }
    size_t capacity = input_length + input_length / 8 + 1024;
    unsigned char *compressed = malloc(capacity);
    uint32_t *head = calloc(HASH_SIZE, sizeof(*head));
    uint32_t *previous = calloc(input_length, sizeof(*previous));
    if (compressed == NULL || head == NULL || previous == NULL) {
        free(compressed);
        free(head);
        free(previous);
        (void)snprintf(error, error_length, "cannot allocate compression state");
        return false;
    }

    static const unsigned char header[10] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0xff,
    };
    memcpy(compressed, header, sizeof(header));
    BitWriter writer = {
        .output = compressed,
        .capacity = capacity - 8,
        .used = sizeof(header),
        .pending = 0,
        .pending_bits = 0,
    };
    bool valid = write_bits(&writer, 1, 1) && write_bits(&writer, 1, 2);
    size_t position = 0;
    while (valid && position < input_length) {
        size_t match_length;
        size_t match_distance;
        find_match(
            input,
            input_length,
            position,
            head,
            previous,
            &match_length,
            &match_distance
        );
        if (match_length >= MIN_MATCH) {
            valid = write_length(&writer, match_length) &&
                write_distance(&writer, match_distance);
            for (size_t offset = 0; offset < match_length; offset++) {
                insert_position(
                    input, input_length, position + offset, head, previous
                );
            }
            position += match_length;
        } else {
            valid = write_fixed_symbol(&writer, input[position]);
            insert_position(input, input_length, position, head, previous);
            position++;
        }
    }
    valid = valid && write_fixed_symbol(&writer, 256) && finish_bits(&writer);
    free(head);
    free(previous);
    if (!valid || writer.used > capacity - 8) {
        free(compressed);
        (void)snprintf(error, error_length, "cannot encode compressed document");
        return false;
    }
    uint32_t crc = crc32_bytes(input, input_length);
    write_little_endian(compressed + writer.used, crc);
    write_little_endian(
        compressed + writer.used + 4,
        (uint32_t)(input_length & UINT32_C(0xffffffff))
    );
    writer.used += 8;
    if (writer.used + 32 >= input_length) {
        free(compressed);
        return true;
    }
    *output = compressed;
    *output_length = writer.used;
    return true;
}
