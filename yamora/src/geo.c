#define _POSIX_C_SOURCE 200809L
/* Spherical GeoJSON geometry and query operators; see docs/geospatial.md.
 * Only IEEE-754 arithmetic and sqrt are used: the series below replace the C
 * library's transcendental functions so results are reproducible. */
#if defined(__clang__)
#pragma STDC FP_CONTRACT OFF
#endif
#include "geo.h"

#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PI 3.14159265358979323846
#define DEGREES (PI / 180.0)
#define EDGE_LIMIT (PI - 1e-6)
#define FOLD_LIMIT (PI - 1e-9)
#define HALF_MARGIN 1e-8
#define CACHE_SLOTS 4

static bool fail(char *error, size_t length, const char *message) {
    if (error && length)
        snprintf(error, length, "%s", message);
    return false;
}

/* Vector arithmetic. */
static YDGeoVec add(YDGeoVec a, YDGeoVec b) { return (YDGeoVec){a.x + b.x, a.y + b.y, a.z + b.z}; }
static YDGeoVec sub(YDGeoVec a, YDGeoVec b) { return (YDGeoVec){a.x - b.x, a.y - b.y, a.z - b.z}; }
static YDGeoVec scale(YDGeoVec a, double s) { return (YDGeoVec){a.x * s, a.y * s, a.z * s}; }
static YDGeoVec neg(YDGeoVec a) { return (YDGeoVec){-a.x, -a.y, -a.z}; }
static double dot(YDGeoVec a, YDGeoVec b) { return a.x * b.x + a.y * b.y + a.z * b.z; }
static YDGeoVec cross(YDGeoVec a, YDGeoVec b) {
    return (YDGeoVec){a.y * b.z - a.z * b.y, a.z * b.x - a.x * b.z, a.x * b.y - a.y * b.x};
}
static double norm(YDGeoVec a) { return sqrt(dot(a, a)); }
static YDGeoVec unit(YDGeoVec a) {
    double n = norm(a);
    return n > 0 ? scale(a, 1 / n) : a;
}
static double dist2(YDGeoVec a, YDGeoVec b) {
    YDGeoVec d = sub(a, b);
    return dot(d, d);
}
static double minimum(double a, double b) { return a < b ? a : b; }

/* Taylor series on |r| <= pi/4 with truncation error below 1e-19. */
static double series_sin(double r) {
    double r2 = r * r, s = 1.0 / 355687428096000.0;
    s = s * r2 - 1.0 / 1307674368000.0;
    s = s * r2 + 1.0 / 6227020800.0;
    s = s * r2 - 1.0 / 39916800.0;
    s = s * r2 + 1.0 / 362880.0;
    s = s * r2 - 1.0 / 5040.0;
    s = s * r2 + 1.0 / 120.0;
    s = s * r2 - 1.0 / 6.0;
    return r + r * r2 * s;
}
static double series_cos(double r) {
    double r2 = r * r, c = -1.0 / 6402373705728000.0;
    c = c * r2 + 1.0 / 20922789888000.0;
    c = c * r2 - 1.0 / 87178291200.0;
    c = c * r2 + 1.0 / 479001600.0;
    c = c * r2 - 1.0 / 3628800.0;
    c = c * r2 + 1.0 / 40320.0;
    c = c * r2 - 1.0 / 720.0;
    c = c * r2 + 1.0 / 24.0;
    c = c * r2 - 0.5;
    return 1 + r2 * c;
}
/* Cody-Waite reduction by pi/2 with a 33-bit leading constant. */
static void sincos_exact(double x, double *s, double *c) {
    static const double pio2_1 = 1.57079632673412561417e+00, pio2_1t = 6.07710050650619224932e-11;
    double k = floor(x * (2.0 / PI) + 0.5);
    double r = (x - k * pio2_1) - k * pio2_1t;
    long long q = (long long)k;
    int quadrant = (int)(((q % 4) + 4) % 4);
    double sr = series_sin(r), cr = series_cos(r);
    switch (quadrant) {
    case 0: *s = sr; *c = cr; break;
    case 1: *s = cr; *c = -sr; break;
    case 2: *s = -sr; *c = -cr; break;
    default: *s = -cr; *c = sr; break;
    }
}
double yd_geo_sin(double radians) {
    double s, c;
    sincos_exact(radians, &s, &c);
    return s;
}
double yd_geo_cos(double radians) {
    double s, c;
    sincos_exact(radians, &s, &c);
    return c;
}
/* atan on |t| <= tan(pi/12), truncation error below 2e-19. */
static double series_atan(double t) {
    double t2 = t * t, s = 1.0 / 29;
    static const double odd[] = {27, 25, 23, 21, 19, 17, 15, 13, 11, 9, 7, 5, 3};
    for (size_t i = 0; i < sizeof(odd) / sizeof(*odd); i++)
        s = s * t2 + (i % 2 ? 1.0 : -1.0) / odd[i];
    return t + t * t2 * s;
}
double yd_geo_atan2(double y, double x) {
    double ax = fabs(x), ay = fabs(y);
    if (ax == 0 && ay == 0)
        return 0;
    bool swap = ay > ax;
    double t = swap ? ax / ay : ay / ax, a;
    static const double root3 = 1.7320508075688772935;
    if (t > 0.26794919243112270647)
        a = PI / 6 + series_atan((t * root3 - 1) / (root3 + t));
    else
        a = series_atan(t);
    if (swap)
        a = PI / 2 - a;
    if (x < 0)
        a = PI - a;
    return y < 0 ? -a : a;
}

YDGeoVec yd_geo_point(double lng, double lat) {
    double sl, cl, sp, cp;
    sincos_exact(lat * DEGREES, &sp, &cp);
    sincos_exact(lng * DEGREES, &sl, &cl);
    return unit((YDGeoVec){cp * cl, cp * sl, sp});
}
double yd_geo_angle(YDGeoVec a, YDGeoVec b) { return yd_geo_atan2(norm(cross(a, b)), dot(a, b)); }

double yd_geo_arc_distance(YDGeoVec p, YDGeoVec a, YDGeoVec b) {
    YDGeoVec n = cross(a, b);
    if (dot(n, n) > 0 && dot(cross(n, a), p) > 0 && dot(cross(b, n), p) > 0)
        return yd_geo_atan2(fabs(dot(p, n)), norm(cross(p, n)));
    return minimum(yd_geo_angle(p, a), yd_geo_angle(p, b));
}
bool yd_geo_near_arc(YDGeoVec p, YDGeoVec a, YDGeoVec b, double tol) {
    double chord = tol * tol;
    if (dist2(p, a) <= chord || dist2(p, b) <= chord)
        return true;
    YDGeoVec n = cross(a, b);
    double size = norm(n);
    if (size == 0 || fabs(dot(p, n)) > tol * size)
        return false;
    return dot(cross(n, a), p) >= 0 && dot(cross(b, n), p) >= 0;
}
/* Interiors of minor arcs ab and cd cross at one point. */
static bool proper_cross(YDGeoVec a, YDGeoVec b, YDGeoVec c, YDGeoVec d) {
    YDGeoVec n1 = cross(a, b), n2 = cross(c, d);
    double sc = dot(n1, c), sd = dot(n1, d);
    if (!((sc > 0 && sd < 0) || (sc < 0 && sd > 0)))
        return false;
    double sa = dot(n2, a), sb = dot(n2, b);
    if (!((sa > 0 && sb < 0) || (sa < 0 && sb > 0)))
        return false;
    YDGeoVec y = cross(n1, n2);
    if (dot(y, add(c, d)) < 0)
        y = neg(y);
    return dot(y, add(a, b)) > 0;
}
bool yd_geo_arcs_touch(YDGeoVec a, YDGeoVec b, YDGeoVec c, YDGeoVec d, double tol) {
    return proper_cross(a, b, c, d) || yd_geo_near_arc(a, c, d, tol) ||
           yd_geo_near_arc(b, c, d, tol) || yd_geo_near_arc(c, a, b, tol) ||
           yd_geo_near_arc(d, a, b, tol);
}
/* Conservative: cos(r1 + r2 + pad) >= cos(r1 + r2) - pad, and both radii
 * are below pi/2. The extra margin absorbs rounding in long-edge caps. */
bool yd_geo_caps_near(const YDGeoCap *a, const YDGeoCap *b, double pad) {
    return dot(a->c, b->c) >= a->cosr * b->cosr - a->sinr * b->sinr - pad - 1e-9;
}

/* Crossings of ring edges by the minor arc r->p, with each vertex assigned to
 * one side of the arc's great circle so shared vertices count once. */
static size_t crossings(YDGeoVec r, YDGeoVec p, const YDGeoChain *ring) {
    YDGeoVec n = cross(r, p), rp = add(r, p);
    double limit = 1 + dot(r, p);
    size_t count = 0;
    bool first = dot(n, ring->v[0]) > 0, side = first;
    for (size_t i = 0; i < ring->n; i++) {
        YDGeoVec u = ring->v[i], w = ring->v[(i + 1) % ring->n];
        bool next = i + 1 == ring->n ? first : dot(n, w) > 0;
        if (side != next) {
            YDGeoVec y = cross(n, cross(u, w));
            double size = norm(y);
            if (size > 0) {
                y = scale(y, 1 / size);
                if (dot(y, add(u, w)) < 0)
                    y = neg(y);
                if (dot(y, rp) >= limit)
                    count++;
            }
        }
        side = next;
    }
    return count;
}
static bool near_chain(const YDGeoChain *chain, YDGeoVec p, double tol) {
    if (chain->n == 1)
        return dist2(p, chain->v[0]) <= tol * tol;
    for (size_t i = 0; i < chain->edges; i++)
        if (yd_geo_near_arc(p, chain->v[i], chain->v[(i + 1) % chain->n], tol))
            return true;
    return false;
}
/* 0 outside, 1 inside, 2 on the closed boundary. */
static int ring_locate(const YDGeoChain *ring, YDGeoVec p) {
    if (near_chain(ring, p, YD_GEO_TOLERANCE))
        return 2;
    bool near = dot(p, ring->ref) >= 0;
    bool inside = near ? true : ring->far_inside;
    if (crossings(near ? ring->ref : neg(ring->ref), p, ring) % 2)
        inside = !inside;
    return inside ? 1 : 0;
}
static int polygon_locate(const YDGeoPart *polygon, YDGeoVec p) {
    int shell = ring_locate(&polygon->chains[0], p);
    if (shell != 1)
        return shell;
    for (size_t i = 1; i < polygon->count; i++) {
        int hole = ring_locate(&polygon->chains[i], p);
        if (hole == 2)
            return 2;
        if (hole == 1)
            return 0;
    }
    return 1;
}
bool yd_geo_part_contains(const YDGeoPart *part, YDGeoVec point) {
    if (part->type == YD_GEO_POLYGON_PART)
        return polygon_locate(part, point) != 0;
    return near_chain(&part->chains[0], point, YD_GEO_TOLERANCE);
}

/* Parsing. */
typedef enum { POINT, MULTIPOINT, LINE, MULTILINE, POLYGON, MULTIPOLYGON } Kind;
typedef struct {
    size_t parts, chains, vertices, positions;
    char *error;
    size_t length;
} Measure;

static bool number(const YDValue *value, double *out) {
    if (!value || (value->type != YD_INT && value->type != YD_FLOAT))
        return false;
    long double n = value->number;
    if (!(n == n) || n > 1e300L || n < -1e300L)
        return false;
    *out = (double)n;
    return isfinite(*out);
}
static bool position(const YDValue *value, double *lng, double *lat, char *error, size_t length) {
    if (!value || value->type != YD_ARRAY || value->count != 2 || !number(value->items[0], lng) ||
        !number(value->items[1], lat))
        return fail(error, length, "geometry positions must be [longitude, latitude] numbers");
    if (*lng < -180 || *lng > 180 || *lat < -90 || *lat > 90)
        return fail(error, length,
                    "geometry longitudes must be within [-180, 180] and latitudes within [-90, 90]");
    return true;
}
static bool spend_positions(Measure *m, size_t count) {
    if (count > YD_GEO_VERTEX_LIMIT - m->positions)
        return fail(m->error, m->length, "geometry exceeds 4096 positions");
    m->positions += count;
    return true;
}
static bool measure_positions(Measure *m, const YDValue *coordinates) {
    double lng, lat;
    for (size_t i = 0; i < coordinates->count; i++)
        if (!position(coordinates->items[i], &lng, &lat, m->error, m->length))
            return false;
    return true;
}
static bool measure_line(Measure *m, const YDValue *c) {
    if (c->type != YD_ARRAY || c->count < 2)
        return fail(m->error, m->length, "LineString coordinates need at least two positions");
    if (!spend_positions(m, c->count) || !measure_positions(m, c))
        return false;
    m->chains++;
    m->vertices += c->count;
    return true;
}
static bool measure_ring(Measure *m, const YDValue *c) {
    if (c->type != YD_ARRAY || c->count < 4)
        return fail(m->error, m->length, "polygon rings need at least four positions");
    if (!spend_positions(m, c->count) || !measure_positions(m, c))
        return false;
    double a, b, x, y;
    position(c->items[0], &a, &b, NULL, 0);
    position(c->items[c->count - 1], &x, &y, NULL, 0);
    if (a != x || b != y)
        return fail(m->error, m->length, "polygon rings must end at their first position");
    m->chains++;
    m->vertices += c->count - 1;
    return true;
}
static bool measure_polygon(Measure *m, const YDValue *c) {
    if (c->type != YD_ARRAY || !c->count || c->count > YD_GEO_RING_LIMIT)
        return fail(m->error, m->length, "Polygon coordinates need 1 to 64 rings");
    for (size_t i = 0; i < c->count; i++)
        if (!measure_ring(m, c->items[i]))
            return false;
    m->parts++;
    return true;
}
static bool measure_point(Measure *m, const YDValue *c) {
    double lng, lat;
    if (!spend_positions(m, 1) || !position(c, &lng, &lat, m->error, m->length))
        return false;
    m->parts++;
    m->chains++;
    m->vertices++;
    return true;
}
static bool measure(Measure *m, Kind kind, const YDValue *c) {
    if (kind == POINT)
        return measure_point(m, c);
    if (kind == LINE) {
        m->parts++;
        return measure_line(m, c);
    }
    if (kind == POLYGON)
        return measure_polygon(m, c);
    if (c->type != YD_ARRAY || !c->count || c->count > YD_GEO_PART_LIMIT)
        return fail(m->error, m->length, "Multi geometries need 1 to 256 members");
    for (size_t i = 0; i < c->count; i++) {
        bool valid = kind == MULTIPOINT  ? measure_point(m, c->items[i])
                     : kind == MULTILINE ? (m->parts++, measure_line(m, c->items[i]))
                                         : measure_polygon(m, c->items[i]);
        if (!valid)
            return false;
    }
    return true;
}
static bool kind_of(const YDValue *value, Kind *kind, const YDValue **coordinates, char *error,
                    size_t length) {
    if (value && value->type == YD_ARRAY) {
        *kind = POINT;
        *coordinates = value;
        return true;
    }
    if (!value || value->type != YD_MAP)
        return fail(error, length, "geometry must be a GeoJSON mapping or [longitude, latitude]");
    const YDValue *type = yd_get(value, "type"), *c = yd_get(value, "coordinates");
    if (yd_get(value, "crs"))
        return fail(error, length, "geometry crs members are unsupported");
    if (value->count != 2 || !type || !c)
        return fail(error, length, "geometry must contain exactly type and coordinates");
    static const char *const names[] = {"Point",      "MultiPoint", "LineString",
                                        "MultiLineString", "Polygon", "MultiPolygon"};
    if (type->type == YD_STRING)
        for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++)
            if (!strcmp(type->scalar, names[i])) {
                *kind = (Kind)i;
                *coordinates = c;
                return true;
            }
    if (type->type == YD_STRING && !strcmp(type->scalar, "GeometryCollection"))
        return fail(error, length, "GeometryCollection is unsupported");
    return fail(error, length, "unknown geometry type");
}

typedef struct {
    YDGeoPart *part;
    YDGeoChain *chain;
    YDGeoVec *vertex;
    YDGeoCap *cap;
} Fill;
static void fill_chain(Fill *f, const YDValue *c, bool ring, bool single) {
    YDGeoChain *chain = f->chain++;
    size_t n = single ? 1 : ring ? c->count - 1 : c->count;
    *chain = (YDGeoChain){.v = f->vertex, .n = n, .ring = ring, .caps = f->cap};
    for (size_t i = 0; i < n; i++) {
        double lng = 0, lat = 0; /* measured valid before filling */
        position(single ? c : c->items[i], &lng, &lat, NULL, 0);
        chain->v[i] = yd_geo_point(lng, lat);
    }
    chain->edges = ring ? n : n - 1;
    f->vertex += n;
    f->cap += chain->edges;
}
static void fill_part(Fill *f, YDGeoPartType type, const YDValue *c) {
    YDGeoPart *part = f->part++;
    part->type = type;
    part->chains = f->chain;
    part->count = type == YD_GEO_POLYGON_PART ? c->count : 1;
    if (type == YD_GEO_POLYGON_PART)
        for (size_t i = 0; i < c->count; i++)
            fill_chain(f, c->items[i], true, false);
    else
        fill_chain(f, c, false, type == YD_GEO_POINT_PART);
}

static double turn(YDGeoVec prev, YDGeoVec at, YDGeoVec next) {
    YDGeoVec in = cross(cross(prev, at), at), out = cross(cross(at, next), at);
    return yd_geo_atan2(dot(at, cross(in, out)), dot(in, out));
}
static bool check_chain(YDGeoChain *chain, char *error, size_t length) {
    for (size_t i = 0; i < chain->edges; i++) {
        double angle = yd_geo_angle(chain->v[i], chain->v[(i + 1) % chain->n]);
        if (angle <= YD_GEO_TOLERANCE)
            return fail(error, length, "geometry repeats a position consecutively");
        if (angle > EDGE_LIMIT)
            return fail(error, length, "geometry edges cannot join antipodal positions");
    }
    if (chain->ring && chain->n < 3)
        return fail(error, length, "polygon rings need three distinct positions");
    return true;
}
static void edge_caps(YDGeoChain *chain) {
    for (size_t i = 0; i < chain->edges; i++) {
        YDGeoVec a = chain->v[i], b = chain->v[(i + 1) % chain->n], c = unit(add(a, b));
        YDGeoVec far = dot(c, a) <= dot(c, b) ? a : b;
        chain->caps[i] = (YDGeoCap){c, dot(c, far), norm(cross(c, far))};
    }
}
/* Gauss-Bonnet: the area left of the ring is 2pi minus its total turning.
 * Rings are reversed so their interior is the smaller region. */
static bool orient_ring(YDGeoChain *chain, char *error, size_t length) {
    size_t n = chain->n;
    double total = 0;
    for (size_t i = 0; i < n; i++) {
        double t = turn(chain->v[(i + n - 1) % n], chain->v[i], chain->v[(i + 1) % n]);
        if (fabs(t) >= FOLD_LIMIT)
            return fail(error, length, "polygon rings cannot fold back on themselves");
        total += t;
    }
    double area = 2 * PI - total;
    if (fabs(area - 2 * PI) < HALF_MARGIN)
        return fail(error, length, "polygon rings must not cross themselves or divide the sphere "
                                   "into equal halves");
    if (area > 2 * PI)
        for (size_t i = 0; i < n / 2; i++) {
            YDGeoVec swap = chain->v[i];
            chain->v[i] = chain->v[n - 1 - i];
            chain->v[n - 1 - i] = swap;
        }
    return true;
}
static double clearance(const YDGeoChain *ring, YDGeoVec p) {
    double best = PI;
    for (size_t i = 0; i < ring->n; i++)
        best = minimum(best, yd_geo_arc_distance(p, ring->v[i], ring->v[(i + 1) % ring->n]));
    return best;
}
/* Offset a vertex into its interior wedge, closer than any other edge. Then
 * determine whether -ref is inside by counting along two quarter circles. */
static void reference(YDGeoChain *ring) {
    size_t n = ring->n, best = 0, tries = n < 16 ? n : 16;
    double best_score = -2, best_angle = PI;
    for (size_t k = 0; k < tries; k++) {
        double angle = PI - turn(ring->v[(k + n - 1) % n], ring->v[k], ring->v[(k + 1) % n]);
        double score = yd_geo_sin(angle / 2);
        if (score > best_score) {
            best_score = score;
            best = k;
            best_angle = angle;
        }
    }
    YDGeoVec at = ring->v[best], next = ring->v[(best + 1) % n], prev = ring->v[(best + n - 1) % n];
    YDGeoVec toward = unit(sub(next, scale(at, dot(next, at)))), left = cross(at, toward);
    double half = best_angle / 2;
    YDGeoVec bisector = add(scale(toward, yd_geo_cos(half)), scale(left, yd_geo_sin(half)));
    double nearest = PI;
    for (size_t i = 0; i < n; i++) {
        if (i == best || (i + 1) % n == best)
            continue;
        nearest = minimum(nearest, yd_geo_arc_distance(at, ring->v[i], ring->v[(i + 1) % n]));
    }
    double epsilon = minimum(minimum(1e-3, nearest / 4),
                             minimum(yd_geo_angle(at, next), yd_geo_angle(prev, at)) / 4);
    ring->ref = unit(add(scale(at, yd_geo_cos(epsilon)), scale(bisector, yd_geo_sin(epsilon))));
    bool large = false;
    for (size_t i = 0; i < n && !large; i++)
        large = dot(ring->v[i], ring->ref) <= 0;
    ring->far_inside = false;
    if (!large)
        return; /* the ring lies in the open hemisphere around ref */
    YDGeoVec r = ring->ref, axis = fabs(r.x) <= fabs(r.y) && fabs(r.x) <= fabs(r.z)
                                        ? (YDGeoVec){1, 0, 0}
                                    : fabs(r.y) <= fabs(r.z) ? (YDGeoVec){0, 1, 0}
                                                             : (YDGeoVec){0, 0, 1};
    YDGeoVec e1 = unit(cross(r, axis)), e2 = cross(r, e1), via = e1;
    double widest = -1;
    for (int k = 0; k < 8; k++) {
        YDGeoVec w = add(scale(e1, yd_geo_cos(k * PI / 4)), scale(e2, yd_geo_sin(k * PI / 4)));
        double room = clearance(ring, w);
        if (room > widest) {
            widest = room;
            via = w;
        }
    }
    ring->far_inside = (crossings(r, via, ring) + crossings(via, neg(r), ring)) % 2 == 0;
}
static bool adjacent(size_t i, size_t j, size_t n) { return j == i + 1 || (i == 0 && j == n - 1); }
/* Rings may not cross or touch themselves or each other; holes lie inside
 * the outer ring and outside each other. */
static bool polygon_simple(const YDGeoPart *polygon, char *error, size_t length) {
    for (size_t r1 = 0; r1 < polygon->count; r1++) {
        const YDGeoChain *a = &polygon->chains[r1];
        for (size_t r2 = r1; r2 < polygon->count; r2++) {
            const YDGeoChain *b = &polygon->chains[r2];
            for (size_t i = 0; i < a->n; i++)
                for (size_t j = r1 == r2 ? i + 1 : 0; j < b->n; j++) {
                    if (r1 == r2 && adjacent(i, j, a->n))
                        continue;
                    if (!yd_geo_caps_near(&a->caps[i], &b->caps[j], YD_GEO_TOLERANCE))
                        continue;
                    if (yd_geo_arcs_touch(a->v[i], a->v[(i + 1) % a->n], b->v[j],
                                          b->v[(j + 1) % b->n], YD_GEO_TOLERANCE))
                        return fail(error, length,
                                    "polygon rings must not intersect themselves or each other");
                }
        }
    }
    for (size_t h = 1; h < polygon->count; h++) {
        if (ring_locate(&polygon->chains[0], polygon->chains[h].v[0]) != 1)
            return fail(error, length, "polygon holes must lie inside the outer ring");
        for (size_t o = 1; o < polygon->count; o++)
            if (o != h && ring_locate(&polygon->chains[o], polygon->chains[h].v[0]) == 1)
                return fail(error, length, "polygon holes must not contain each other");
    }
    return true;
}

void yd_geo_geometry_free(YDGeoGeometry *geometry) {
    if (geometry) {
        free(geometry->parts);
        memset(geometry, 0, sizeof(*geometry));
    }
}
bool yd_geo_parse(const YDValue *value, YDGeoValidation level, YDGeoGeometry *geometry,
                  char *error, size_t length) {
    memset(geometry, 0, sizeof(*geometry));
    Kind kind = POINT;
    const YDValue *c = NULL;
    if (!kind_of(value, &kind, &c, error, length))
        return false;
    Measure m = {.error = error, .length = length};
    if (!measure(&m, kind, c))
        return false;
    size_t bytes = m.parts * sizeof(YDGeoPart) + m.chains * sizeof(YDGeoChain) +
                   m.vertices * (sizeof(YDGeoVec) + sizeof(YDGeoCap));
    unsigned char *block = malloc(bytes);
    if (!block)
        return fail(error, length, "geometry allocation failed");
    Fill f = {.part = (YDGeoPart *)block};
    f.chain = (YDGeoChain *)(block + m.parts * sizeof(YDGeoPart));
    f.vertex = (YDGeoVec *)((unsigned char *)f.chain + m.chains * sizeof(YDGeoChain));
    f.cap = (YDGeoCap *)((unsigned char *)f.vertex + m.vertices * sizeof(YDGeoVec));
    geometry->parts = f.part;
    geometry->count = m.parts;
    geometry->vertices = m.vertices;
    if (kind == POINT || kind == MULTIPOINT) {
        for (size_t i = 0; i < (kind == POINT ? 1 : c->count); i++)
            fill_part(&f, YD_GEO_POINT_PART, kind == POINT ? c : c->items[i]);
        if (kind == POINT) {
            geometry->single_point = true;
            position(c, &geometry->lng, &geometry->lat, NULL, 0);
        }
    } else if (kind == LINE || kind == POLYGON)
        fill_part(&f, kind == LINE ? YD_GEO_LINE_PART : YD_GEO_POLYGON_PART, c);
    else
        for (size_t i = 0; i < c->count; i++)
            fill_part(&f, kind == MULTILINE ? YD_GEO_LINE_PART : YD_GEO_POLYGON_PART, c->items[i]);
    bool valid = true;
    for (size_t p = 0; valid && p < geometry->count; p++) {
        YDGeoPart *part = &geometry->parts[p];
        for (size_t i = 0; valid && i < part->count; i++) {
            YDGeoChain *chain = &part->chains[i];
            valid = check_chain(chain, error, length) &&
                    (!chain->ring || orient_ring(chain, error, length));
            if (valid) {
                edge_caps(chain);
                if (chain->ring)
                    reference(chain);
            }
        }
        if (valid && level == YD_GEO_FULL && part->type == YD_GEO_POLYGON_PART)
            valid = polygon_simple(part, error, length);
    }
    if (!valid)
        yd_geo_geometry_free(geometry);
    return valid;
}

/* Predicates. Boundaries are closed within YD_GEO_TOLERANCE. */
static double chain_distance(const YDGeoChain *chain, YDGeoVec p) {
    if (chain->n == 1)
        return yd_geo_angle(p, chain->v[0]);
    double best = PI;
    for (size_t i = 0; i < chain->edges; i++)
        best = minimum(best, yd_geo_arc_distance(p, chain->v[i], chain->v[(i + 1) % chain->n]));
    return best;
}
static double part_distance(const YDGeoPart *part, YDGeoVec p) {
    if (part->type == YD_GEO_POLYGON_PART && polygon_locate(part, p))
        return 0;
    double best = PI;
    for (size_t i = 0; i < part->count; i++)
        best = minimum(best, chain_distance(&part->chains[i], p));
    return best;
}
double yd_geo_distance(YDGeoVec point, const YDGeoGeometry *geometry) {
    double best = PI;
    for (size_t i = 0; i < geometry->count; i++)
        best = minimum(best, part_distance(&geometry->parts[i], point));
    return best;
}
static bool chains_touch(const YDGeoChain *a, const YDGeoChain *b) {
    for (size_t i = 0; i < a->edges; i++)
        for (size_t j = 0; j < b->edges; j++)
            if (yd_geo_caps_near(&a->caps[i], &b->caps[j], YD_GEO_TOLERANCE) &&
                yd_geo_arcs_touch(a->v[i], a->v[(i + 1) % a->n], b->v[j], b->v[(j + 1) % b->n],
                                  YD_GEO_TOLERANCE))
                return true;
    return false;
}
static bool chains_cross(const YDGeoChain *a, const YDGeoChain *b) {
    for (size_t i = 0; i < a->edges; i++)
        for (size_t j = 0; j < b->edges; j++)
            if (yd_geo_caps_near(&a->caps[i], &b->caps[j], 0) &&
                proper_cross(a->v[i], a->v[(i + 1) % a->n], b->v[j], b->v[(j + 1) % b->n]))
                return true;
    return false;
}
static bool parts_intersect(const YDGeoPart *a, const YDGeoPart *b) {
    if (a->type == YD_GEO_POINT_PART)
        return yd_geo_part_contains(b, a->chains[0].v[0]);
    if (b->type == YD_GEO_POINT_PART)
        return yd_geo_part_contains(a, b->chains[0].v[0]);
    for (size_t i = 0; i < a->count; i++)
        for (size_t j = 0; j < b->count; j++)
            if (chains_touch(&a->chains[i], &b->chains[j]))
                return true;
    /* Without boundary contact one part lies wholly inside the other or not. */
    return (b->type == YD_GEO_POLYGON_PART && polygon_locate(b, a->chains[0].v[0])) ||
           (a->type == YD_GEO_POLYGON_PART && polygon_locate(a, b->chains[0].v[0]));
}
bool yd_geo_intersects(const YDGeoGeometry *a, const YDGeoGeometry *b) {
    for (size_t i = 0; i < a->count; i++)
        for (size_t j = 0; j < b->count; j++)
            if (parts_intersect(&a->parts[i], &b->parts[j]))
                return true;
    return false;
}
static bool part_within(const YDGeoPart *a, const YDGeoPart *polygon) {
    for (size_t i = 0; i < a->count; i++)
        for (size_t k = 0; k < a->chains[i].n; k++)
            if (!polygon_locate(polygon, a->chains[i].v[k]))
                return false;
    if (a->type == YD_GEO_POINT_PART)
        return true;
    for (size_t i = 0; i < a->count; i++)
        for (size_t j = 0; j < polygon->count; j++)
            if (chains_cross(&a->chains[i], &polygon->chains[j]))
                return false;
    if (a->type == YD_GEO_POLYGON_PART)
        for (size_t h = 1; h < polygon->count; h++)
            if (polygon_locate(a, polygon->chains[h].v[0]) == 1)
                return false;
    return true;
}
bool yd_geo_within(const YDGeoGeometry *inner, const YDGeoGeometry *outer) {
    for (size_t j = 0; j < outer->count; j++)
        if (outer->parts[j].type != YD_GEO_POLYGON_PART)
            return false;
    for (size_t i = 0; i < inner->count; i++) {
        bool inside = false;
        for (size_t j = 0; !inside && j < outer->count; j++)
            inside = part_within(&inner->parts[i], &outer->parts[j]);
        if (!inside)
            return false;
    }
    return true;
}
bool yd_geo_within_cap(const YDGeoGeometry *geometry, YDGeoVec center, double radius) {
    return radius >= PI || yd_geo_distance(neg(center), geometry) >= PI - radius - YD_GEO_TOLERANCE;
}

/* Query operators. */
typedef enum { SHAPE_GEOMETRY, SHAPE_CAP, SHAPE_BOX, SHAPE_FLAT_POLYGON } ShapeKind;
typedef struct {
    ShapeKind kind;
    YDGeoRegion region;
    double box[4], *xy;
    size_t n;
} Shape;

static void shape_free(Shape *shape) {
    yd_geo_geometry_free(&shape->region.geometry);
    free(shape->xy);
    memset(shape, 0, sizeof(*shape));
}
static bool flat_position(const YDValue *value, double *x, double *y, char *error, size_t length) {
    if (!value || value->type != YD_ARRAY || value->count != 2 || !number(value->items[0], x) ||
        !number(value->items[1], y))
        return fail(error, length, "legacy shape positions must be [x, y] numbers");
    return true;
}
static bool compile(const char *op, const YDValue *operand, YDGeoValidation level, Shape *shape,
                    char *error, size_t length) {
    memset(shape, 0, sizeof(*shape));
    bool within = !strcmp(op, "$geoWithin");
    if (!operand || operand->type != YD_MAP || operand->count != 1)
        return fail(error, length, within ? "$geoWithin requires exactly one of $geometry, "
                                            "$centerSphere, $box or $polygon"
                                          : "$geoIntersects requires exactly $geometry");
    const char *key = operand->keys[0];
    const YDValue *value = operand->items[0];
    if (!strcmp(key, "$geometry")) {
        if (!value || value->type != YD_MAP)
            return fail(error, length, "$geometry must be a GeoJSON mapping");
        if (!yd_geo_parse(value, level, &shape->region.geometry, error, length))
            return false;
        for (size_t i = 0; within && i < shape->region.geometry.count; i++)
            if (shape->region.geometry.parts[i].type != YD_GEO_POLYGON_PART) {
                shape_free(shape);
                return fail(error, length, "$geoWithin $geometry must be a Polygon or MultiPolygon");
            }
        shape->kind = SHAPE_GEOMETRY;
        return true;
    }
    if (!within)
        return fail(error, length, "$geoIntersects requires exactly $geometry");
    if (!strcmp(key, "$centerSphere")) {
        double lng, lat, radius;
        if (!value || value->type != YD_ARRAY || value->count != 2 ||
            !position(value->items[0], &lng, &lat, error, length))
            return value && value->type == YD_ARRAY && value->count == 2
                       ? false
                       : fail(error, length, "$centerSphere requires [[longitude, latitude], radians]");
        if (!number(value->items[1], &radius) || radius < 0 || radius > PI)
            return fail(error, length, "$centerSphere radius must be 0 to pi radians");
        shape->kind = SHAPE_CAP;
        shape->region.cap = true;
        shape->region.center = yd_geo_point(lng, lat);
        shape->region.radius = radius;
        return true;
    }
    if (!strcmp(key, "$box")) {
        double x1, y1, x2, y2;
        if (!value || value->type != YD_ARRAY || value->count != 2)
            return fail(error, length, "$box requires [[x, y], [x, y]]");
        if (!flat_position(value->items[0], &x1, &y1, error, length) ||
            !flat_position(value->items[1], &x2, &y2, error, length))
            return false;
        shape->kind = SHAPE_BOX;
        shape->box[0] = minimum(x1, x2);
        shape->box[1] = minimum(y1, y2);
        shape->box[2] = x1 < x2 ? x2 : x1;
        shape->box[3] = y1 < y2 ? y2 : y1;
        return true;
    }
    if (!strcmp(key, "$polygon")) {
        if (!value || value->type != YD_ARRAY || value->count < 3 ||
            value->count > YD_GEO_VERTEX_LIMIT)
            return fail(error, length, "$polygon requires 3 to 4096 [x, y] positions");
        shape->xy = malloc(value->count * 2 * sizeof(double));
        if (!shape->xy)
            return fail(error, length, "geometry allocation failed");
        for (size_t i = 0; i < value->count; i++)
            if (!flat_position(value->items[i], &shape->xy[2 * i], &shape->xy[2 * i + 1], error,
                               length)) {
                shape_free(shape);
                return false;
            }
        shape->kind = SHAPE_FLAT_POLYGON;
        shape->n = value->count;
        return true;
    }
    return fail(error, length,
                "$geoWithin requires exactly one of $geometry, $centerSphere, $box or $polygon");
}
/* Flat legacy shapes compare a single position as planar x/y values; the
 * closed boundary includes points exactly on an edge. */
static bool flat_polygon(const Shape *shape, double px, double py) {
    bool inside = false;
    for (size_t i = 0, j = shape->n - 1; i < shape->n; j = i++) {
        double xi = shape->xy[2 * i], yi = shape->xy[2 * i + 1];
        double xj = shape->xy[2 * j], yj = shape->xy[2 * j + 1];
        if ((xj - xi) * (py - yi) - (yj - yi) * (px - xi) == 0 && px >= minimum(xi, xj) &&
            px <= (xi < xj ? xj : xi) && py >= minimum(yi, yj) && py <= (yi < yj ? yj : yi))
            return true;
        if ((yi > py) != (yj > py) && px < (xj - xi) * (py - yi) / (yj - yi) + xi)
            inside = !inside;
    }
    return inside;
}
static bool shape_match(const Shape *shape, bool within, const YDGeoGeometry *g) {
    switch (shape->kind) {
    case SHAPE_GEOMETRY:
        return within ? yd_geo_within(g, &shape->region.geometry)
                      : yd_geo_intersects(g, &shape->region.geometry);
    case SHAPE_CAP:
        return yd_geo_within_cap(g, shape->region.center, shape->region.radius);
    case SHAPE_BOX:
        return g->single_point && g->lng >= shape->box[0] && g->lng <= shape->box[2] &&
               g->lat >= shape->box[1] && g->lat <= shape->box[3];
    default:
        return g->single_point && flat_polygon(shape, g->lng, g->lat);
    }
}

bool yd_geo_operator(const char *op) {
    return !strcmp(op, "$geoWithin") || !strcmp(op, "$geoIntersects") || !strcmp(op, "$near") ||
           !strcmp(op, "$nearSphere") || !strcmp(op, "$minDistance") ||
           !strcmp(op, "$maxDistance");
}
int yd_geo_validate_operator(const char *op, const YDValue *operand, char *error, size_t length) {
    if (!yd_geo_operator(op))
        return 0;
    if (!strcmp(op, "$near") || !strcmp(op, "$nearSphere")) {
        fail(error, length, "$near and $nearSphere must be the only operator of a top-level "
                            "filter field with a geo index");
        return -1;
    }
    if (!strcmp(op, "$minDistance") || !strcmp(op, "$maxDistance")) {
        fail(error, length, "$minDistance and $maxDistance belong inside $near");
        return -1;
    }
    Shape shape;
    if (!compile(op, operand, YD_GEO_FULL, &shape, error, length))
        return -1;
    shape_free(&shape);
    return 1;
}
int yd_geo_region(const char *op, const YDValue *operand, YDGeoRegion *region, char *error,
                  size_t length) {
    memset(region, 0, sizeof(*region));
    Shape shape;
    if (!compile(op, operand, YD_GEO_LIGHT, &shape, error, length))
        return -1;
    if (shape.kind == SHAPE_BOX || shape.kind == SHAPE_FLAT_POLYGON) {
        shape_free(&shape);
        return 0;
    }
    *region = shape.region;
    free(shape.xy);
    return 1;
}
void yd_geo_region_free(YDGeoRegion *region) {
    if (region) {
        yd_geo_geometry_free(&region->geometry);
        memset(region, 0, sizeof(*region));
    }
}
bool yd_geo_near(const YDValue *operand, YDGeoNear *near, char *error, size_t length) {
    memset(near, 0, sizeof(*near));
    if (!operand || operand->type != YD_MAP)
        return fail(error, length,
                    "$near requires {$geometry: Point}; legacy coordinate pairs are unsupported");
    for (size_t i = 0; i < operand->count; i++)
        if (strcmp(operand->keys[i], "$geometry") && strcmp(operand->keys[i], "$minDistance") &&
            strcmp(operand->keys[i], "$maxDistance"))
            return fail(error, length, "$near accepts only $geometry, $minDistance and $maxDistance");
    const YDValue *geometry = yd_get(operand, "$geometry");
    const YDValue *type = geometry && geometry->type == YD_MAP ? yd_get(geometry, "type") : NULL;
    if (!type || type->type != YD_STRING || strcmp(type->scalar, "Point"))
        return fail(error, length, "$near $geometry must be a GeoJSON Point");
    YDGeoGeometry point;
    if (!yd_geo_parse(geometry, YD_GEO_FULL, &point, error, length))
        return false;
    near->center = point.parts[0].chains[0].v[0];
    near->lng = point.lng;
    near->lat = point.lat;
    yd_geo_geometry_free(&point);
    near->min_meters = 0;
    near->max_meters = PI * YD_GEO_EARTH_RADIUS_METERS;
    const char *names[] = {"$minDistance", "$maxDistance"};
    double *targets[] = {&near->min_meters, &near->max_meters};
    for (size_t i = 0; i < 2; i++) {
        const YDValue *value = yd_get(operand, names[i]);
        if (value && (!number(value, targets[i]) || *targets[i] < 0))
            return fail(error, length, "$minDistance and $maxDistance must be non-negative metres");
    }
    if (near->min_meters > near->max_meters)
        return fail(error, length, "$minDistance cannot exceed $maxDistance");
    return true;
}

/* Compiled operands are shared by every document a query examines. A slot is
 * reused only for a structurally equal operand, so stale addresses are safe. */
typedef struct {
    YDValue *key;
    bool within;
    uint64_t hash, used;
    unsigned refs;
    Shape *shape;
} Slot;
static pthread_mutex_t cache_lock = PTHREAD_MUTEX_INITIALIZER;
static Slot cache[CACHE_SLOTS];
static uint64_t cache_clock;

static uint64_t mix(uint64_t hash, const void *data, size_t size) {
    const unsigned char *bytes = data;
    for (size_t i = 0; i < size; i++)
        hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
    return hash;
}
static uint64_t value_hash(const YDValue *value, uint64_t hash, unsigned depth) {
    if (!value || depth > YD_DEPTH_LIMIT)
        return mix(hash, "-", 1);
    if (value->type == YD_INT || value->type == YD_FLOAT) {
        double n = (double)value->number;
        return mix(mix(hash, "#", 1), &n, sizeof(n));
    }
    hash = mix(hash, &value->type, sizeof(value->type));
    if (value->type == YD_STRING)
        return mix(hash, value->scalar, strlen(value->scalar));
    if (value->type == YD_BOOL)
        return mix(hash, &value->boolean, sizeof(value->boolean));
    for (size_t i = 0; i < value->count; i++) {
        if (value->type == YD_MAP)
            hash = mix(hash, value->keys[i], strlen(value->keys[i]) + 1);
        hash = value_hash(value->items[i], hash, depth + 1);
    }
    return hash;
}
static Shape *acquire(bool within, const YDValue *operand, Slot **slot) {
    uint64_t hash = value_hash(operand, within ? UINT64_C(14695981039346656037) : 7, 0);
    *slot = NULL;
    pthread_mutex_lock(&cache_lock);
    for (size_t i = 0; i < CACHE_SLOTS; i++)
        if (cache[i].key && cache[i].hash == hash && cache[i].within == within &&
            yd_equal(cache[i].key, operand)) {
            cache[i].refs++;
            cache[i].used = ++cache_clock;
            *slot = &cache[i];
            pthread_mutex_unlock(&cache_lock);
            return cache[i].shape;
        }
    pthread_mutex_unlock(&cache_lock);
    Shape *shape = calloc(1, sizeof(*shape));
    char ignored[8];
    if (!shape ||
        !compile(within ? "$geoWithin" : "$geoIntersects", operand, YD_GEO_LIGHT, shape, ignored,
                 sizeof(ignored))) {
        free(shape);
        return NULL;
    }
    YDValue *key = yd_clone(operand);
    pthread_mutex_lock(&cache_lock);
    Slot *victim = NULL;
    for (size_t i = 0; key && i < CACHE_SLOTS; i++)
        if (!cache[i].refs && (!victim || !cache[i].key || (victim->key && cache[i].used < victim->used)))
            victim = &cache[i];
    if (victim) {
        yd_free(victim->key);
        if (victim->shape)
            shape_free(victim->shape);
        free(victim->shape);
        *victim = (Slot){key, within, hash, ++cache_clock, 1, shape};
        *slot = victim;
        key = NULL;
    }
    pthread_mutex_unlock(&cache_lock);
    yd_free(key);
    return shape;
}
static void release(Slot *slot, Shape *shape) {
    if (slot) {
        pthread_mutex_lock(&cache_lock);
        slot->refs--;
        pthread_mutex_unlock(&cache_lock);
    } else {
        shape_free(shape);
        free(shape);
    }
}
bool yd_geo_match(const YDValue *actual, const char *op, const YDValue *operand, size_t *cost) {
    *cost = 1;
    bool within = !strcmp(op, "$geoWithin");
    if (!actual || (!within && strcmp(op, "$geoIntersects")))
        return false;
    YDGeoGeometry geometry;
    char ignored[8];
    if (!yd_geo_parse(actual, YD_GEO_LIGHT, &geometry, ignored, sizeof(ignored)))
        return false;
    Slot *slot;
    Shape *shape = acquire(within, operand, &slot);
    bool matched = false;
    if (shape) {
        size_t other = shape->kind == SHAPE_GEOMETRY ? shape->region.geometry.vertices : shape->n;
        *cost = 1 + geometry.vertices + other + geometry.vertices * other / 64;
        matched = shape_match(shape, within, &geometry);
        release(slot, shape);
    }
    yd_geo_geometry_free(&geometry);
    return matched;
}

/* Index catalog extension. */
bool yd_geo_index_kind(const YDValue *definition) {
    const YDValue *kind =
        definition && definition->type == YD_MAP ? yd_get(definition, "type") : NULL;
    return kind && kind->type == YD_STRING && !strcmp(kind->scalar, "geo");
}
bool yd_geo_index_definition(const YDValue *definition, char *error, size_t length) {
    static const char *const allowed[] = {"collection", "name", "fields", "type", "unique"};
    for (size_t i = 0; i < definition->count; i++) {
        bool known = false;
        for (size_t j = 0; j < sizeof(allowed) / sizeof(*allowed); j++)
            known = known || !strcmp(definition->keys[i], allowed[j]);
        if (!known)
            return fail(error, length,
                        "geo indexes accept only collection, name, fields, type and unique");
    }
    const YDValue *fields = yd_get(definition, "fields"), *unique = yd_get(definition, "unique");
    if (!fields || fields->type != YD_ARRAY || fields->count != 1 ||
        fields->items[0]->type != YD_STRING || fields->items[0]->scalar[0] == '$')
        return fail(error, length, "geo indexes need exactly one field path");
    if (unique && (unique->type != YD_BOOL || unique->boolean))
        return fail(error, length, "geo indexes cannot be unique");
    return true;
}
void yd_geo_index_strip_type(YDValue *definition) {
    for (size_t j = 0; j < definition->count; j++) {
        if (strcmp(definition->keys[j], "type"))
            continue;
        free(definition->keys[j]);
        yd_free(definition->items[j]);
        size_t remaining = definition->count - j - 1;
        memmove(definition->keys + j, definition->keys + j + 1, remaining * sizeof(char *));
        memmove(definition->items + j, definition->items + j + 1, remaining * sizeof(YDValue *));
        definition->count--;
        return;
    }
}
bool yd_geo_field(const YDValue *document, const char *path, const YDValue **value, char *error,
                  size_t length) {
    /* The value is exactly what query evaluation reads. A field name applied
     * to a sequence of mappings is refused, so array-traversing path rules
     * can never select values the index did not store. */
    *value = NULL;
    const YDValue *at = document;
    const char *segment = path;
    while (at && *segment) {
        const char *dot = strchr(segment, '.');
        size_t n = dot ? (size_t)(dot - segment) : strlen(segment);
        const YDValue *next = NULL;
        if (at->type == YD_MAP) {
            for (size_t i = 0; i < at->count && !next; i++)
                if (strlen(at->keys[i]) == n && !memcmp(at->keys[i], segment, n))
                    next = at->items[i];
        } else if (at->type == YD_ARRAY) {
            bool index = n && !(n > 1 && *segment == '0');
            for (size_t i = 0; index && i < n; i++)
                index = segment[i] >= '0' && segment[i] <= '9';
            if (!index) {
                for (size_t i = 0; i < at->count; i++)
                    if (at->items[i]->type == YD_MAP)
                        return fail(error, length,
                                    "geo index paths cannot cross a sequence of mappings");
                break;
            }
            char digits[24];
            if (n >= sizeof(digits))
                break;
            memcpy(digits, segment, n);
            digits[n] = 0;
            next = yd_path(at, digits);
        }
        at = next;
        if (!dot)
            break;
        segment = dot + 1;
    }
    *value = yd_path(document, path);
    return true;
}
