/* Batch driver for the geometry and cell modules. Each stdin line holds one
 * JSON command mapping; stdout receives one JSON line per command. */
#define _POSIX_C_SOURCE 200809L
#include "geo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void quoted(const char *text) {
    putchar('"');
    for (const char *p = text; *p; p++) {
        if (*p == '"' || *p == '\\')
            putchar('\\');
        putchar(*p);
    }
    putchar('"');
}
static int failure(const char *error) {
    printf("{\"ok\":false,\"error\":");
    quoted(error);
    printf("}\n");
    return 0;
}
static bool point(const YDValue *value, YDGeoVec *out) {
    if (!value || value->type != YD_ARRAY || value->count != 2)
        return false;
    *out = yd_geo_point((double)value->items[0]->number, (double)value->items[1]->number);
    return true;
}
static void cells(const uint64_t *list, size_t n) {
    printf("{\"ok\":true,\"cells\":[");
    for (size_t i = 0; i < n; i++) {
        char token[YD_GEO_TOKEN_SIZE];
        yd_geo_cell_token(list[i], token);
        printf("%s\"%s\"", i ? "," : "", token);
    }
    printf("]}\n");
}
static int run(const YDValue *command) {
    const YDValue *op = yd_get(command, "op");
    const char *name = op && op->type == YD_STRING ? op->scalar : "";
    char error[256] = "";
    if (!strcmp(name, "parse")) {
        const YDValue *full = yd_get(command, "full");
        YDGeoGeometry g;
        if (!yd_geo_parse(yd_get(command, "value"), full && full->boolean ? YD_GEO_FULL : YD_GEO_LIGHT,
                          &g, error, sizeof(error)))
            return failure(error);
        printf("{\"ok\":true,\"parts\":%zu,\"vertices\":%zu}\n", g.count, g.vertices);
        yd_geo_geometry_free(&g);
    } else if (!strcmp(name, "match")) {
        const char *kind = yd_get(command, "operator")->scalar;
        const YDValue *operand = yd_get(command, "operand");
        int valid = yd_geo_validate_operator(kind, operand, error, sizeof(error));
        if (valid <= 0)
            return failure(valid ? error : "not a geo operator");
        size_t cost = 0;
        bool match = yd_geo_match(yd_get(command, "value"), kind, operand, &cost);
        printf("{\"ok\":true,\"match\":%s,\"cost\":%zu}\n", match ? "true" : "false", cost);
    } else if (!strcmp(name, "distance")) {
        YDGeoVec p;
        YDGeoGeometry g;
        if (!point(yd_get(command, "point"), &p))
            return failure("point");
        if (!yd_geo_parse(yd_get(command, "value"), YD_GEO_LIGHT, &g, error, sizeof(error)))
            return failure(error);
        printf("{\"ok\":true,\"meters\":%.17g}\n",
               yd_geo_distance(p, &g) * YD_GEO_EARTH_RADIUS_METERS);
        yd_geo_geometry_free(&g);
    } else if (!strcmp(name, "tokens")) {
        char tokens[YD_GEO_INDEX_CELLS][YD_GEO_TOKEN_SIZE];
        size_t n = 0;
        if (!yd_geo_index_tokens(yd_get(command, "value"), tokens, &n, error, sizeof(error)))
            return failure(error);
        printf("{\"ok\":true,\"cells\":[");
        for (size_t i = 0; i < n; i++)
            printf("%s\"%s\"", i ? "," : "", tokens[i]);
        printf("]}\n");
    } else if (!strcmp(name, "cover")) {
        YDGeoRegion region;
        if (yd_geo_region(yd_get(command, "operator")->scalar, yd_get(command, "operand"), &region,
                          error,
                          sizeof(error)) != 1)
            return failure(error[0] ? error : "flat");
        uint64_t list[YD_GEO_QUERY_CELLS];
        size_t n = yd_geo_cover_region(&region, YD_GEO_QUERY_CELLS, YD_GEO_MAX_LEVEL, list);
        yd_geo_region_free(&region);
        cells(list, n);
    } else if (!strcmp(name, "cap")) {
        YDGeoVec c;
        if (!point(yd_get(command, "point"), &c))
            return failure("point");
        YDGeoRegion region = {.cap = true, .center = c,
                              .radius = (double)yd_get(command, "radius")->number};
        uint64_t list[YD_GEO_QUERY_CELLS];
        cells(list, yd_geo_cover_region(&region, YD_GEO_QUERY_CELLS, YD_GEO_MAX_LEVEL, list));
    } else if (!strcmp(name, "leaf")) {
        YDGeoVec p;
        if (!point(yd_get(command, "point"), &p))
            return failure("point");
        uint64_t leaf = yd_geo_cell_leaf(p);
        cells(&leaf, 1);
    } else if (!strcmp(name, "trig")) {
        double x = (double)yd_get(command, "x")->number, y = (double)yd_get(command, "y")->number;
        printf("{\"ok\":true,\"sin\":%.17g,\"cos\":%.17g,\"atan2\":%.17g}\n", yd_geo_sin(x),
               yd_geo_cos(x), yd_geo_atan2(y, x));
    } else
        failure("unknown command");
    return 0;
}
int main(void) {
    char *line = NULL, error[256];
    size_t capacity = 0;
    ssize_t n;
    int status = 0;
    while ((n = getline(&line, &capacity, stdin)) > 0) {
        YDValue *command = yd_parse_sized((const unsigned char *)line, (size_t)n,
                                          YD_LARGE_REQUEST_LIMIT, error, sizeof(error));
        if (!command || command->type != YD_MAP) {
            fprintf(stderr, "invalid command: %s\n", command ? "not a mapping" : error);
            yd_free(command);
            status = 2;
            break;
        }
        run(command);
        yd_free(command);
    }
    free(line);
    return status;
}
