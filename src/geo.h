#ifndef YAMORA_GEO_H
#define YAMORA_GEO_H
/* Spherical GeoJSON geometry, query operators and index cells. The model,
 * precision and limits are documented in docs/geospatial.md. Every
 * computation uses only IEEE-754 +, -, *, / and sqrt, so cell tokens and
 * predicate results do not depend on the compiler's or C library's
 * transcendental functions. */
#include "value.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define YD_GEO_EARTH_RADIUS_METERS 6378100.0
#define YD_GEO_VERTEX_LIMIT 4096U
#define YD_GEO_PART_LIMIT 256U
#define YD_GEO_RING_LIMIT 64U
/* Closed boundaries: points within this angle (about 6.4 micrometres) of an
 * edge or vertex are on it. */
#define YD_GEO_TOLERANCE 1e-12
/* Coverings include every cell within this angle (about 6.4 millimetres). */
#define YD_GEO_PAD 1e-9
#define YD_GEO_INDEX_CELLS 32U
#define YD_GEO_QUERY_CELLS 64U
#define YD_GEO_MAX_LEVEL 30
/* Point documents store their leaf cell; other geometries store at most
 * YD_GEO_INDEX_CELLS cells no finer than this level. */
#define YD_GEO_DOCUMENT_LEVEL 24
#define YD_GEO_TOKEN_SIZE 17U

typedef struct {
    double x, y, z;
} YDGeoVec;

typedef enum { YD_GEO_POINT_PART, YD_GEO_LINE_PART, YD_GEO_POLYGON_PART } YDGeoPartType;

/* Bounding cap of one edge: unit center, cosine and sine of its radius. */
typedef struct {
    YDGeoVec c;
    double cosr, sinr;
} YDGeoCap;

/* A line, or a ring without its closing position. Rings run counter-clockwise
 * around their interior, which is always the smaller side. ref is interior;
 * the status of -ref is far_inside. caps has one entry per edge. */
typedef struct {
    YDGeoVec *v;
    size_t n, edges;
    bool ring;
    YDGeoCap *caps;
    YDGeoVec ref;
    bool far_inside;
} YDGeoChain;

typedef struct {
    YDGeoPartType type;
    YDGeoChain *chains; /* point: one chain of one vertex; polygon: shell, holes */
    size_t count;
} YDGeoPart;

typedef struct {
    YDGeoPart *parts;
    size_t count, vertices;
    /* One position (a GeoJSON Point or a legacy pair) for flat legacy shapes. */
    bool single_point;
    double lng, lat;
} YDGeoGeometry;

typedef enum {
    YD_GEO_LIGHT, /* structure, ranges, rings and orientation */
    YD_GEO_FULL   /* also self-intersection and hole placement */
} YDGeoValidation;

/* Parses a GeoJSON geometry mapping or a legacy [longitude, latitude] pair.
 * On failure the geometry is empty and error names the first problem. */
bool yd_geo_parse(const YDValue *value, YDGeoValidation level, YDGeoGeometry *geometry,
                  char *error, size_t length);
void yd_geo_geometry_free(YDGeoGeometry *geometry);

YDGeoVec yd_geo_point(double lng, double lat);
double yd_geo_angle(YDGeoVec a, YDGeoVec b);
double yd_geo_atan2(double y, double x);
/* Shared primitives: angle from p to the minor arc ab; p within tol of it;
 * arcs ab and cd within tol of each other; two caps within pad. */
double yd_geo_arc_distance(YDGeoVec p, YDGeoVec a, YDGeoVec b);
bool yd_geo_near_arc(YDGeoVec p, YDGeoVec a, YDGeoVec b, double tol);
bool yd_geo_arcs_touch(YDGeoVec a, YDGeoVec b, YDGeoVec c, YDGeoVec d, double tol);
bool yd_geo_caps_near(const YDGeoCap *a, const YDGeoCap *b, double pad);
double yd_geo_distance(YDGeoVec point, const YDGeoGeometry *geometry);
bool yd_geo_intersects(const YDGeoGeometry *a, const YDGeoGeometry *b);
bool yd_geo_within(const YDGeoGeometry *inner, const YDGeoGeometry *outer);
bool yd_geo_within_cap(const YDGeoGeometry *geometry, YDGeoVec center, double radius);
bool yd_geo_part_contains(const YDGeoPart *part, YDGeoVec point);
double yd_geo_cos(double radians);
double yd_geo_sin(double radians);

/* Field query operators. A geo operator is one of $geoWithin, $geoIntersects,
 * $near, $nearSphere, $minDistance and $maxDistance. */
bool yd_geo_operator(const char *op);
/* Returns 0 for other operators, 1 for a valid operand and -1 with error.
 * $near and its distances are valid only in a top-level geo index query. */
int yd_geo_validate_operator(const char *op, const YDValue *operand, char *error, size_t length);
/* Evaluates a validated $geoWithin or $geoIntersects operand against one
 * field value. cost receives the work units to charge. */
bool yd_geo_match(const YDValue *actual, const char *op, const YDValue *operand, size_t *cost);

/* A spherical query region compiled from a validated operand. */
typedef struct {
    bool cap;
    YDGeoVec center;
    double radius;
    YDGeoGeometry geometry;
} YDGeoRegion;
/* Returns 1 for a spherical $geoWithin/$geoIntersects operand, 0 for a flat
 * legacy shape that cannot use a spherical index, or -1 with error. */
int yd_geo_region(const char *op, const YDValue *operand, YDGeoRegion *region, char *error,
                  size_t length);
void yd_geo_region_free(YDGeoRegion *region);

typedef struct {
    YDGeoVec center;
    double lng, lat, min_meters, max_meters;
} YDGeoNear;
bool yd_geo_near(const YDValue *operand, YDGeoNear *near, char *error, size_t length);

/* Index catalog extension: a definition is geo when type is "geo". */
bool yd_geo_index_kind(const YDValue *definition);
bool yd_geo_index_definition(const YDValue *definition, char *error, size_t length);
void yd_geo_index_strip_type(YDValue *definition);

/* Cells: 64-bit identifiers on six cube faces, levels 0..30, written as
 * 16 lowercase hexadecimal digits. Ranges cover a cell's descendants. */
uint64_t yd_geo_cell_leaf(YDGeoVec point);
int yd_geo_cell_level(uint64_t cell);
uint64_t yd_geo_cell_parent(uint64_t cell, int level);
uint64_t yd_geo_cell_range_min(uint64_t cell);
uint64_t yd_geo_cell_range_max(uint64_t cell);
void yd_geo_cell_token(uint64_t cell, char token[YD_GEO_TOKEN_SIZE]);
/* Deterministic covering of the region padded by YD_GEO_PAD, sorted. */
size_t yd_geo_cover_region(const YDGeoRegion *region, size_t max_cells, int max_level,
                           uint64_t *cells);
size_t yd_geo_cover_geometry(const YDGeoGeometry *geometry, size_t max_cells, int max_level,
                             uint64_t *cells);
/* Index tokens for one document field value. Missing and null values have
 * none; other values must be valid geometry. */
bool yd_geo_index_tokens(const YDValue *value, char tokens[][YD_GEO_TOKEN_SIZE], size_t *count,
                         char *error, size_t length);
/* The value at a dotted path for a geo index. Paths may not traverse a
 * sequence except through a canonical decimal index. */
bool yd_geo_field(const YDValue *document, const char *path, const YDValue **value, char *error,
                  size_t length);
#endif
