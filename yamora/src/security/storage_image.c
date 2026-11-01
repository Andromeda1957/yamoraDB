#define _GNU_SOURCE
#include "storage_image.h"
#include "storage_image_native.h"
#include "disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define STAGE_PREFIX ".yamora-sealed-"
#define STAGE_LIMIT 4U
struct YDStorageImage {
    atomic_size_t references;
    pid_t process;
    pthread_mutex_t lock;
    int directory, memory;
    unsigned char *mapping;
    size_t maximum;
    struct stat root, selected;
    bool published, failed;
    const YDKeyProvider *provider;
    char key_id[YD_KEY_ID_MAX + 1];
    YDEnvelopeIdentity identity;
    YDDisk *disk;
    void (*finalizer)(void *);
    void *finalizer_context;
};
static bool failure(char *error, size_t length, const char *message) {
    if (error && length) snprintf(error, length, "%s", message);
    return false;
}
static bool disabled(void) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return false;
    if (prior == PTHREAD_CANCEL_DISABLE) return true;
    (void)pthread_setcancelstate(prior, NULL);
    return false;
}
static bool live(const YDStorageImage *image) {
    return image && image->process == getpid();
}
static bool private_directory(const struct stat *s) {
    return S_ISDIR(s->st_mode) && s->st_uid == geteuid() && (s->st_mode & 07777) == 0700;
}
static bool private_file(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() && s->st_nlink == 1 &&
        (s->st_mode & 07777) == 0600 && s->st_size > 0 &&
        (uint64_t)s->st_size <= YD_ENVELOPE_WIRE_MAX;
}
static bool same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool io(int fd, unsigned char *bytes, size_t length, bool writing) {
    size_t at = 0;
    while (at < length) {
        ssize_t n = writing ? pwrite(fd, bytes + at, length - at, (off_t)at) :
            pread(fd, bytes + at, length - at, (off_t)at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        at += (size_t)n;
    }
    return true;
}
static bool stage_name(const char *name) {
    if (strlen(name) != sizeof(STAGE_PREFIX) - 1 + 32 ||
        memcmp(name, STAGE_PREFIX, sizeof(STAGE_PREFIX) - 1)) return false;
    for (const char *p = name + sizeof(STAGE_PREFIX) - 1; *p; p++)
        if (!(*p >= '0' && *p <= '9') && !(*p >= 'a' && *p <= 'f')) return false;
    return true;
}
static bool namespace_valid(int directory, bool initializing, bool allow_stages) {
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *scan = fd >= 0 ? fdopendir(fd) : NULL;
    if (!scan) { if (fd >= 0) close(fd); return false; }
    unsigned stages = 0, selected = 0;
    bool valid = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(scan);
        if (!entry) { if (errno) valid = false; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (initializing) { valid = false; break; }
        struct stat s;
        if (fstatat(directory, entry->d_name, &s, AT_SYMLINK_NOFOLLOW)) {
            valid = false; break;
        }
        if (!strcmp(entry->d_name, YD_DISK_FILE)) {
            if (!private_file(&s)) { valid = false; break; }
            selected++;
        } else if (!allow_stages || !stage_name(entry->d_name) || ++stages >= STAGE_LIMIT ||
            !S_ISREG(s.st_mode) || s.st_uid != geteuid() || s.st_nlink != 1 ||
            (s.st_mode & 07777) != 0600 || s.st_size < 0 ||
            (uint64_t)s.st_size > YD_ENVELOPE_WIRE_MAX) { valid = false; break; }
    }
    if (closedir(scan)) valid = false;
    return valid && (initializing ? selected == 0 : selected == 1);
}
static int directory_lock(int borrowed, struct stat *out) {
    int fd = openat(borrowed, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, out) || !private_directory(out) || flock(fd, LOCK_EX | LOCK_NB)) {
        close(fd); return -1;
    }
    return fd;
}
static bool root_binding(int fd, const struct stat *original) {
    struct stat actual;
    return !fstat(fd, &actual) && private_directory(&actual) &&
        actual.st_dev == original->st_dev && actual.st_ino == original->st_ino &&
        actual.st_mode == original->st_mode && actual.st_uid == original->st_uid &&
        actual.st_gid == original->st_gid;
}
static bool verified_cipher(int fd, const unsigned char *wire, size_t length) {
    unsigned char buffer[4096];
    size_t at = 0;
    while (at < length) {
        size_t count = length - at;
        if (count > sizeof(buffer)) count = sizeof(buffer);
        size_t read = 0;
        while (read < count) {
            ssize_t n = pread(fd, buffer + read, count - read, (off_t)(at + read));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return false;
            read += (size_t)n;
        }
        if (memcmp(buffer, wire + at, count)) return false;
        at += count;
    }
    return true;
}
static bool binding(YDStorageImage *image) {
    struct stat selected;
    if (!root_binding(image->directory, &image->root)) return false;
    int result = fstatat(image->directory, YD_DISK_FILE, &selected, AT_SYMLINK_NOFOLLOW);
    return image->published ? result == 0 && private_file(&selected) && same(&image->selected, &selected) :
        result < 0 && errno == ENOENT;
}
static unsigned char *selected_wire(YDStorageImage *image, size_t *length) {
    *length = 0;
    if (!binding(image) || !image->published) return NULL;
    int fd = openat(image->directory, YD_DISK_FILE, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat s, after;
    bool valid = fd >= 0 && !fstat(fd, &s) && same(&s, &image->selected);
    size_t size = valid ? (size_t)s.st_size : 0;
    unsigned char *wire = valid ? malloc(size) : NULL;
    valid = wire && io(fd, wire, size, false) && !fstat(fd, &after) && same(&s, &after) && binding(image);
    if (fd >= 0) close(fd);
    if (!valid) { yd_envelope_free(wire, size); return NULL; }
    *length = size;
    return wire;
}
static bool publish_wire(YDStorageImage *image, unsigned char *wire, size_t size) {
    if (!binding(image) || !namespace_valid(image->directory, !image->published, true)) return false;
    unsigned char random[16];
    if (RAND_bytes(random, sizeof(random)) != 1) return false;
    static const char hex[] = "0123456789abcdef";
    char name[sizeof(STAGE_PREFIX) + 32];
    memcpy(name, STAGE_PREFIX, sizeof(STAGE_PREFIX) - 1);
    for (size_t i = 0; i < sizeof(random); i++) {
        name[sizeof(STAGE_PREFIX) - 1 + 2 * i] = hex[random[i] >> 4];
        name[sizeof(STAGE_PREFIX) + 2 * i] = hex[random[i] & 15];
    }
    name[sizeof(name) - 1] = 0;
    int fd = openat(image->directory, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat s, named, after;
    bool valid = fd >= 0 && io(fd, wire, size, true) && !fsync(fd) && !fstat(fd, &s) &&
        private_file(&s) && (size_t)s.st_size == size && verified_cipher(fd, wire, size) &&
        !fstatat(image->directory, name, &named, AT_SYMLINK_NOFOLLOW) && same(&s, &named) &&
        binding(image) && !renameat(image->directory, name, image->directory, YD_DISK_FILE) &&
        !fsync(image->directory) && !fstat(fd, &after) && private_file(&after) &&
        after.st_dev == s.st_dev && after.st_ino == s.st_ino && (size_t)after.st_size == size &&
        !fstatat(image->directory, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) && same(&after, &named) &&
        root_binding(image->directory, &image->root) && namespace_valid(image->directory, false, true) &&
        verified_cipher(fd, wire, size);
    if (valid) image->selected = after;
    if (fd >= 0) close(fd);
    /* A partial/uncertain ciphertext stage is deliberately preserved. Nothing
     * in this module infers disposal authority from its name or apparent age. */
    return valid;
}
static bool retain(void *context) {
    YDStorageImage *image = context;
    if (!live(image)) return false;
    size_t count = atomic_load_explicit(&image->references, memory_order_relaxed);
    while (count && count < SIZE_MAX) {
        if (atomic_compare_exchange_weak_explicit(&image->references, &count, count + 1,
            memory_order_relaxed, memory_order_relaxed)) return true;
    }
    return false;
}
static void release(void *context) {
    YDStorageImage *image = context;
    if (!live(image) || atomic_fetch_sub_explicit(&image->references, 1, memory_order_acq_rel) != 1) return;
    if (image->mapping) {
        OPENSSL_cleanse(image->mapping, image->maximum);
        (void)munmap(image->mapping, image->maximum);
    }
    if (image->memory >= 0) close(image->memory);
    if (image->directory >= 0) close(image->directory);
    pthread_mutex_destroy(&image->lock);
    void (*finalizer)(void *) = image->finalizer;
    void *finalizer_context = image->finalizer_context;
    OPENSSL_cleanse(image, sizeof(*image));
    free(image);
    if (finalizer) finalizer(finalizer_context);
}
static bool persist(void *context, int fd, const YDDiskView *view, char *error, size_t length) {
    YDStorageImage *image = context;
    if (!live(image) || !disabled() || !view) return false;
    pthread_mutex_lock(&image->lock);
    struct stat memory, supplied;
    bool valid = !image->failed && view->format == 5 && view->end >= 8192 &&
        !(view->end % YD_DISK_PAGE) && view->end <= image->maximum &&
        !fstat(image->memory, &memory) && !fstat(fd, &supplied) &&
        memory.st_dev == supplied.st_dev && memory.st_ino == supplied.st_ino &&
        (uint64_t)memory.st_size == image->maximum &&
        (!image->published || image->identity.generation < UINT64_MAX);
    YDEnvelopeIdentity next = image->identity;
    if (image->published) next.generation++;
    unsigned char *wire = NULL;
    size_t size = 0;
    if (valid) valid = yd_envelope_seal(image->provider, image->key_id, &next,
        image->mapping, (size_t)view->end, &wire, &size) == YD_ENVELOPE_OK;
    if (valid) valid = publish_wire(image, wire, size);
    yd_envelope_free(wire, size);
    if (valid) { image->published = true; image->identity = next; }
    else image->failed = true;
    pthread_mutex_unlock(&image->lock);
    return valid || failure(error, length, "encrypted native publication failed; preserve artifacts and restart");
}
static bool options_valid(const YDStorageImageOptions *options, const char *key_id) {
    if (!options || !key_id || !*key_id || strnlen(key_id, YD_KEY_ID_MAX + 1) > YD_KEY_ID_MAX ||
        options->expected.kind != YD_STORAGE_IMAGE_KIND || !options->expected.generation ||
        (options->initialize && options->expected.generation != 1) ||
        options->maximum_bytes < 8192 || options->maximum_bytes > YD_STORAGE_IMAGE_MAX ||
        options->maximum_bytes % YD_DISK_PAGE || options->cache_bytes < 32768 ||
        options->cache_bytes > (size_t)1024 * 1024 * 1024) return false;
    unsigned char store = 0, object = 0;
    for (size_t i = 0; i < sizeof(options->expected.store_id); i++) store |= options->expected.store_id[i];
    for (size_t i = 0; i < sizeof(options->expected.object_id); i++) object |= options->expected.object_id[i];
    return store && object;
}
YDStorageImage *yd_storage_image_open_at(int directory, const YDKeyProvider *provider,
    const char *key_id, const YDStorageImageOptions *options, char *error, size_t length) {
    if (!disabled() || !provider || !options_valid(options, key_id)) {
        failure(error, length, "invalid encrypted profile options or cancellation state"); return NULL;
    }
    YDStorageImage *image = calloc(1, sizeof(*image));
    if (!image) return NULL;
    image->directory = image->memory = -1;
    image->process = getpid();
    atomic_init(&image->references, 1);
    if (pthread_mutex_init(&image->lock, NULL)) { free(image); return NULL; }
    image->maximum = (size_t)options->maximum_bytes;
    image->identity = options->expected;
    image->provider = provider;
    memcpy(image->key_id, key_id, strlen(key_id) + 1);
    image->directory = directory_lock(directory, &image->root);
    if (image->directory < 0 || !namespace_valid(image->directory, options->initialize, true)) goto failed;
    unsigned char *plain = NULL, *wire = NULL;
    size_t plain_size = 0, wire_size = 0;
    if (!options->initialize) {
        if (fstatat(image->directory, YD_DISK_FILE, &image->selected, AT_SYMLINK_NOFOLLOW) ||
            !private_file(&image->selected)) goto failed;
        image->published = true;
        wire = selected_wire(image, &wire_size);
        bool valid = wire && yd_envelope_open(provider, &options->expected, wire, wire_size,
            &plain, &plain_size) == YD_ENVELOPE_OK && plain_size >= 8192 &&
            !(plain_size % YD_DISK_PAGE) && plain_size <= image->maximum;
        yd_envelope_free(wire, wire_size);
        if (!valid) { yd_envelope_free(plain, plain_size); goto failed; }
    }
#ifdef __linux__
    image->memory = memfd_create("yamora-encrypted-native", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (image->memory >= 0 && !fchmod(image->memory, 0600) &&
        !ftruncate(image->memory, (off_t)image->maximum)) {
        void *mapped = mmap(NULL, image->maximum, PROT_READ | PROT_WRITE, MAP_SHARED, image->memory, 0);
        if (mapped != MAP_FAILED) image->mapping = mapped;
    }
    /* mlock2(flags=0) has mlock semantics, including eager population. Common
     * sanitizer runtimes replace mlock with a success-returning no-op; mlock2
     * avoids that interceptor so qualification still locks real kernel pages.
     * Missing syscall/libc/kernel support refuses; no unlocked fallback. */
    if (!image->mapping || mlock2(image->mapping, image->maximum, 0) ||
        madvise(image->mapping, image->maximum, MADV_DONTDUMP) ||
        fcntl(image->memory, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)) {
        yd_envelope_free(plain, plain_size); goto failed;
    }
#else
    yd_envelope_free(plain, plain_size); goto failed;
#endif
    if (plain) memcpy(image->mapping, plain, plain_size);
    yd_envelope_free(plain, plain_size);
    YDDiskImagePersistence persistence = {image, persist, retain, release};
    image->disk = yd_disk_open_image_fd(image->memory, options->initialize,
        options->cache_bytes, options->maximum_bytes, plain_size, &persistence, error, length);
    if (image->disk) return image;
failed:
    release(image);
    failure(error, length, "encrypted native open refused; preserve files and verify key, identity, mode and locked-memory budget");
    return NULL;
}
YDDisk *yd_storage_image_disk(YDStorageImage *image) {
    return live(image) ? image->disk : NULL;
}
bool yd_storage_image_on_last_close(YDStorageImage *image, void (*finalizer)(void *), void *context) {
    if (!live(image) || !disabled() || !finalizer || !context || image->finalizer ||
        atomic_load_explicit(&image->references, memory_order_relaxed) != 2) return false;
    image->finalizer = finalizer;
    image->finalizer_context = context;
    return true;
}
bool yd_storage_image_identity(YDStorageImage *image, YDEnvelopeIdentity *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!live(image) || !out || !disabled()) return false;
    pthread_mutex_lock(&image->lock);
    bool valid = image->published && !image->failed;
    if (valid) *out = image->identity;
    pthread_mutex_unlock(&image->lock);
    return valid;
}
bool yd_storage_image_backup_at(YDStorageImage *image, int destination,
    YDEnvelopeIdentity *out, char *error, size_t length) {
    if (out) memset(out, 0, sizeof(*out));
    if (!live(image) || !out || !disabled()) return false;
    struct stat root;
    int directory = directory_lock(destination, &root);
    bool valid = directory >= 0 && namespace_valid(directory, true, false);
    pthread_mutex_lock(&image->lock);
    size_t size = 0;
    unsigned char *wire = valid && !image->failed ? selected_wire(image, &size) : NULL;
    int fd = wire ? openat(directory, YD_DISK_FILE,
        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600) : -1;
    struct stat written, named;
    valid = fd >= 0 && io(fd, wire, size, true) && !fsync(fd) && !fsync(directory) &&
        !fstat(fd, &written) && private_file(&written) && (size_t)written.st_size == size &&
        !fstatat(directory, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) && same(&written, &named) &&
        root_binding(directory, &root) && namespace_valid(directory, false, false) &&
        verified_cipher(fd, wire, size);
    if (valid) *out = image->identity;
    if (fd >= 0) close(fd);
    yd_envelope_free(wire, size);
    pthread_mutex_unlock(&image->lock);
    if (directory >= 0) close(directory);
    return valid || failure(error, length, "encrypted backup failed; preserve destination artifacts");
}
bool yd_storage_image_restore_at(int backup, int destination, const YDKeyProvider *provider,
    const char *key_id, const YDStorageImageOptions *options, char *error, size_t length) {
    if (!options || options->initialize) return failure(error, length, "restore requires exact existing backup identity");
    YDStorageImage *image = yd_storage_image_open_at(backup, provider, key_id, options, error, length);
    if (!image) return false;
    YDEnvelopeIdentity saved;
    bool valid = yd_storage_image_backup_at(image, destination, &saved, error, length);
    yd_storage_image_close(image);
    return valid;
}
bool yd_storage_image_rotate(YDStorageImage *image, const YDKeyProvider *target,
    const char *key_id, char *error, size_t length) {
    if (!live(image) || !disabled() || !target || !key_id || !*key_id ||
        strnlen(key_id, YD_KEY_ID_MAX + 1) > YD_KEY_ID_MAX) return false;
    YDDisk *disk = image->disk;
    if (!disk || !yd_disk_process_valid(disk)) return false;
    pthread_mutex_lock(&disk->writer);
    pthread_mutex_lock(&image->lock);
    size_t size = 0, rotated_size = 0;
    unsigned char *wire = !image->failed && image->identity.generation < UINT64_MAX ?
        selected_wire(image, &size) : NULL;
    unsigned char *rotated = NULL;
    bool valid = wire && yd_envelope_rotate(image->provider, target, key_id, &image->identity,
        image->identity.generation + 1, wire, size, &rotated, &rotated_size) == YD_ENVELOPE_OK &&
        publish_wire(image, rotated, rotated_size);
    yd_envelope_free(wire, size);
    yd_envelope_free(rotated, rotated_size);
    if (valid) {
        image->identity.generation++;
        image->provider = target;
        memcpy(image->key_id, key_id, strlen(key_id) + 1);
    } else {
        image->failed = true;
    }
    pthread_mutex_unlock(&image->lock);
    /* Keep writer custody through native fencing, without nesting the native
     * root mutex beneath the image mutex. Pins retain their completed old view. */
    if (!valid) {
        pthread_mutex_lock(&disk->root_lock);
        disk->failed = true;
        pthread_cond_broadcast(&disk->published);
        pthread_mutex_unlock(&disk->root_lock);
    }
    pthread_mutex_unlock(&disk->writer);
    return valid || failure(error, length, "encrypted rotation failed; writer fenced, preserve files");
}
void yd_storage_image_close(YDStorageImage *image) {
    if (!live(image) || !disabled()) return;
    YDDisk *disk = image->disk;
    image->disk = NULL;
    yd_disk_close(disk);
    release(image);
}
