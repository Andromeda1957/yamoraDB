#ifndef YAMORA_DISK_GEO_H
#define YAMORA_DISK_GEO_H
#include "disk_documents.h"
/* Geo index plans for native queries; see docs/geospatial.md. A top-level
 * $near or $nearSphere over a geo-indexed field, and a top-level $geoWithin
 * or $geoIntersects whose field has a geo index, set handled and return the
 * page or NULL with error. Otherwise handled stays false and the caller plans
 * the query normally, which scans for the remaining geo operators. */
char *yd_disk_geo_query(YDDisk *disk, const YDDiskView *view, const char *collection,
                        const YDValue *spec, size_t *size, bool *handled, char *error,
                        size_t length);
#endif
