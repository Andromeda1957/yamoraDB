#define _POSIX_C_SOURCE 200809L
/* Cube-face cells and deterministic coverings for geo indexes; see
 * docs/geospatial.md. A cell id is face << 61, then two bits per level with
 * the i bit above the j bit, then a marker bit. Its 16 lowercase hex digits
 * sort in id order, so descendants of a cell form one contiguous key range. */
#if defined(__clang__)
#pragma STDC FP_CONTRACT OFF
#endif
#include "geo.h"

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PI 3.14159265358979323846
#define CELL_CAPACITY (YD_GEO_QUERY_CELLS + 8U)

enum { OUTSIDE, BOUNDARY, INSIDE };

typedef struct {
    int face, level;
    uint32_t i, j;
} Cell;
typedef struct {
    YDGeoVec v[4], n[4], center;
    double size[4];
    YDGeoCap cap;
} Shape;

static double dot(YDGeoVec a, YDGeoVec b) { return a.x * b.x + a.y * b.y + a.z * b.z; }
static YDGeoVec cross(YDGeoVec a, YDGeoVec b) {
    return (YDGeoVec){a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x};
}
static YDGeoVec unit(YDGeoVec a) {
    double n = sqrt(dot(a, a));
    return (YDGeoVec){a.x / n, a.y / n, a.z / n};
}

static YDGeoVec face_point(int face, double u, double v) {
    double s = face < 3 ? 1 : -1;
    switch (face % 3) {
    case 0: return unit((YDGeoVec){s, u, v});
    case 1: return unit((YDGeoVec){v, s, u});
    default: return unit((YDGeoVec){u, v, s});
    }
}
static uint32_t coordinate(double u) {
    double t = floor((u + 1) * 536870912.0);
    if (!(t >= 0))
        return 0;
    return t > 1073741823.0 ? 1073741823U : (uint32_t)t;
}
static uint64_t cell_id(const Cell *c) {
    uint64_t position = 0;
    for (int b = c->level - 1; b >= 0; b--)
        position = (position << 2) | ((uint64_t)((c->i >> b) & 1U) << 1) | ((c->j >> b) & 1U);
    return ((uint64_t)c->face << 61) | (position << (61 - 2 * c->level)) |
           (UINT64_C(1) << (60 - 2 * c->level));
}
static uint64_t lowest(uint64_t cell) { return cell & (0 - cell); }

uint64_t yd_geo_cell_leaf(YDGeoVec p) {
    double ax = fabs(p.x), ay = fabs(p.y), az = fabs(p.z), major, u, v;
    int axis = ax >= ay && ax >= az ? 0 : ay >= az ? 1 : 2;
    if (axis == 0) {
        major = p.x;
        u = p.y;
        v = p.z;
    } else if (axis == 1) {
        major = p.y;
        u = p.z;
        v = p.x;
    } else {
        major = p.z;
        u = p.x;
        v = p.y;
    }
    Cell c = {axis + (major < 0 ? 3 : 0), YD_GEO_MAX_LEVEL, coordinate(u / fabs(major)),
              coordinate(v / fabs(major))};
    return cell_id(&c);
}
int yd_geo_cell_level(uint64_t cell) {
    int zeros = 0;
    while (zeros < 60 && !((cell >> zeros) & 1U))
        zeros++;
    return YD_GEO_MAX_LEVEL - zeros / 2;
}
uint64_t yd_geo_cell_parent(uint64_t cell, int level) {
    uint64_t bit = UINT64_C(1) << (60 - 2 * level);
    return (cell & (0 - bit)) | bit;
}
uint64_t yd_geo_cell_range_min(uint64_t cell) { return cell - (lowest(cell) - 1); }
uint64_t yd_geo_cell_range_max(uint64_t cell) { return cell + (lowest(cell) - 1); }
void yd_geo_cell_token(uint64_t cell, char token[YD_GEO_TOKEN_SIZE]) {
    snprintf(token, YD_GEO_TOKEN_SIZE, "%016" PRIx64, cell);
}

static void cell_shape(const Cell *c, Shape *s) {
    double step = 2.0 / (double)(UINT64_C(1) << c->level);
    double u0 = -1 + c->i * step, u1 = -1 + (c->i + 1) * step;
    double v0 = -1 + c->j * step, v1 = -1 + (c->j + 1) * step;
    s->v[0] = face_point(c->face, u0, v0);
    s->v[1] = face_point(c->face, u1, v0);
    s->v[2] = face_point(c->face, u1, v1);
    s->v[3] = face_point(c->face, u0, v1);
    s->center = face_point(c->face, (u0 + u1) / 2, (v0 + v1) / 2);
    for (int k = 0; k < 4; k++)
        s->n[k] = cross(s->v[k], s->v[(k + 1) % 4]);
    bool flip = dot(s->n[0], s->center) < 0;
    double cosr = 1;
    for (int k = 0; k < 4; k++) {
        if (flip)
            s->n[k] = (YDGeoVec){-s->n[k].x, -s->n[k].y, -s->n[k].z};
        s->size[k] = sqrt(dot(s->n[k], s->n[k]));
        double c = dot(s->center, s->v[k]);
        cosr = c < cosr ? c : cosr;
    }
    s->cap = (YDGeoCap){s->center, cosr, sqrt(1 - cosr * cosr)};
}
/* Inside the cell widened by pad on every side. */
static bool in_cell(const Shape *s, YDGeoVec p, double pad) {
    if (dot(p, s->center) <= 0)
        return false;
    for (int k = 0; k < 4; k++)
        if (dot(p, s->n[k]) < -pad * s->size[k])
            return false;
    return true;
}
static bool edge_touches(const Shape *s, YDGeoVec a, YDGeoVec b, const YDGeoCap *cap) {
    if (!yd_geo_caps_near(cap, &s->cap, YD_GEO_PAD))
        return false;
    if (in_cell(s, a, YD_GEO_PAD) || in_cell(s, b, YD_GEO_PAD))
        return true;
    for (int k = 0; k < 4; k++)
        if (yd_geo_arcs_touch(a, b, s->v[k], s->v[(k + 1) % 4], YD_GEO_PAD))
            return true;
    return false;
}
static bool chain_touches(const Shape *s, const YDGeoChain *chain) {
    if (chain->n == 1)
        return in_cell(s, chain->v[0], YD_GEO_PAD);
    for (size_t e = 0; e < chain->edges; e++)
        if (edge_touches(s, chain->v[e], chain->v[(e + 1) % chain->n], &chain->caps[e]))
            return true;
    return false;
}
/* A cell that no polygon edge comes near is wholly inside or outside it. */
static int classify_geometry(const void *context, const Shape *s) {
    const YDGeoGeometry *g = context;
    bool boundary = false;
    for (size_t p = 0; p < g->count; p++) {
        const YDGeoPart *part = &g->parts[p];
        bool touched = false;
        for (size_t c = 0; !touched && c < part->count; c++)
            touched = chain_touches(s, &part->chains[c]);
        if (touched)
            boundary = true;
        else if (part->type == YD_GEO_POLYGON_PART && yd_geo_part_contains(part, s->center))
            return INSIDE;
    }
    return boundary ? BOUNDARY : OUTSIDE;
}
static int classify_cap(const void *context, const Shape *s) {
    const YDGeoRegion *r = context;
    if (r->radius >= PI)
        return INSIDE;
    double distance = 0;
    if (!in_cell(s, r->center, 0)) {
        distance = PI;
        for (int k = 0; k < 4; k++) {
            double d = yd_geo_arc_distance(r->center, s->v[k], s->v[(k + 1) % 4]);
            distance = d < distance ? d : distance;
        }
    }
    if (distance > r->radius + YD_GEO_PAD)
        return OUTSIDE;
    if (r->radius <= PI / 2) {
        bool inside = true;
        for (int k = 0; inside && k < 4; k++)
            inside = yd_geo_angle(r->center, s->v[k]) <= r->radius - YD_GEO_PAD;
        if (inside)
            return INSIDE;
    }
    return BOUNDARY;
}

static int compare_cells(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}
/* Breadth-first refinement from the six faces. A boundary cell splits while
 * the covering stays within max_cells; inside cells and cells at max_level
 * are kept whole. Every cell within YD_GEO_PAD of the region is covered. */
static size_t cover(int (*classify)(const void *, const Shape *), const void *region,
                    size_t max_cells, int max_level, uint64_t *cells) {
    /* Callers pass at least six cells: the faces alone may need them. */
    if (max_cells > YD_GEO_QUERY_CELLS)
        max_cells = YD_GEO_QUERY_CELLS;
    if (max_level > YD_GEO_MAX_LEVEL)
        max_level = YD_GEO_MAX_LEVEL;
    Cell current[CELL_CAPACITY], next[CELL_CAPACITY];
    int state[CELL_CAPACITY], next_state[CELL_CAPACITY];
    size_t n = 0, result = 0;
    Shape shape;
    for (int face = 0; face < 6; face++) {
        Cell c = {face, 0, 0, 0};
        cell_shape(&c, &shape);
        int s = classify(region, &shape);
        if (s != OUTSIDE) {
            current[n] = c;
            state[n++] = s;
        }
    }
    for (int level = 0; n; level++) {
        size_t m = 0;
        for (size_t k = 0; k < n; k++) {
            const Cell *c = &current[k];
            if (state[k] == INSIDE || level >= max_level) {
                cells[result++] = cell_id(c);
                continue;
            }
            Cell kids[4];
            int kid_state[4];
            size_t found = 0;
            for (uint32_t q = 0; q < 4; q++) {
                Cell kid = {c->face, level + 1, 2 * c->i + (q >> 1), 2 * c->j + (q & 1U)};
                cell_shape(&kid, &shape);
                int s = classify(region, &shape);
                if (s != OUTSIDE) {
                    kids[found] = kid;
                    kid_state[found++] = s;
                }
            }
            if (found && result + m + (n - k - 1) + found <= max_cells) {
                for (size_t q = 0; q < found; q++) {
                    next[m] = kids[q];
                    next_state[m++] = kid_state[q];
                }
            } else
                cells[result++] = cell_id(c);
        }
        memcpy(current, next, m * sizeof(*next));
        memcpy(state, next_state, m * sizeof(*next_state));
        n = m;
    }
    qsort(cells, result, sizeof(*cells), compare_cells);
    return result;
}
size_t yd_geo_cover_region(const YDGeoRegion *region, size_t max_cells, int max_level,
                           uint64_t *cells) {
    return region->cap ? cover(classify_cap, region, max_cells, max_level, cells)
                       : cover(classify_geometry, &region->geometry, max_cells, max_level, cells);
}
size_t yd_geo_cover_geometry(const YDGeoGeometry *geometry, size_t max_cells, int max_level,
                             uint64_t *cells) {
    return cover(classify_geometry, geometry, max_cells, max_level, cells);
}
bool yd_geo_index_tokens(const YDValue *value, char tokens[][YD_GEO_TOKEN_SIZE], size_t *count,
                         char *error, size_t length) {
    *count = 0;
    if (!value || value->type == YD_NULL)
        return true;
    YDGeoGeometry geometry;
    if (!yd_geo_parse(value, YD_GEO_FULL, &geometry, error, length))
        return false;
    uint64_t cells[YD_GEO_INDEX_CELLS];
    size_t n;
    if (geometry.count == 1 && geometry.parts[0].type == YD_GEO_POINT_PART) {
        cells[0] = yd_geo_cell_leaf(geometry.parts[0].chains[0].v[0]);
        n = 1;
    } else
        n = yd_geo_cover_geometry(&geometry, YD_GEO_INDEX_CELLS, YD_GEO_DOCUMENT_LEVEL, cells);
    yd_geo_geometry_free(&geometry);
    if (!n) /* unreachable for valid geometry; the faces cover everything */
        for (int face = 0; face < 6; face++) {
            Cell c = {face, 0, 0, 0};
            cells[n++] = cell_id(&c);
        }
    for (size_t i = 0; i < n; i++)
        yd_geo_cell_token(cells[i], tokens[i]);
    *count = n;
    return true;
}
