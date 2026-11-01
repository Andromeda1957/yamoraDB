/* Extend the actual live three-controller fixture without copying its seed or
 * reaching into the private controller layout. All interposition is test-only. */
#define __wrap_yd_disk_pin selector_original_disk_pin
#include "raft_cluster_application_fixture.c"
#undef __wrap_yd_disk_pin

typedef struct {
    ApplicationFixture *fixture;
    pthread_mutex_t *held[64];
    size_t count, abandoned, queued_with_locks;
    atomic_bool queued;
    bool enabled_entry, returned, retirement_left, observer_error;
} SelectorCancellation;
static _Thread_local SelectorCancellation *cancellation_probe;

int __real_pthread_mutex_lock(pthread_mutex_t *);
int __real_pthread_mutex_unlock(pthread_mutex_t *);
int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
    int result = __real_pthread_mutex_lock(mutex);
    SelectorCancellation *probe = cancellation_probe;
    if (!result && probe) {
        if (probe->count == sizeof(probe->held) / sizeof(*probe->held))
            probe->observer_error = true;
        else probe->held[probe->count++] = mutex;
    }
    return result;
}
int __wrap_pthread_mutex_unlock(pthread_mutex_t *mutex) {
    int result = __real_pthread_mutex_unlock(mutex);
    SelectorCancellation *probe = cancellation_probe;
    if (!result && probe)
        for (size_t i = probe->count; i; i--)
            if (probe->held[i - 1] == mutex) {
                memmove(probe->held + i - 1, probe->held + i,
                    (probe->count - i) * sizeof(*probe->held));
                probe->count--;
                break;
            }
    return result;
}

YDDisk *__wrap_yd_disk_pin(YDDisk *disk,
    size_t cache, char *error, size_t length) {
    SelectorCancellation *probe = cancellation_probe;
    if (probe && probe->enabled_entry && !atomic_exchange(&probe->queued, true)) {
        /* The first nested image_current capture's native pin occurs under the controller
         * mutex, before selection retains any local generation/temporary owner.
         * Never enable cancellation here: the repaired outer selector must keep
         * this real request pending until its own complete cleanup/adoption. */
        probe->queued_with_locks = probe->count;
        if (pthread_cancel(pthread_self())) probe->observer_error = true;
    }
    return selector_original_disk_pin(disk, cache, error, length);
}

static void selector_cancel_cleanup(void *context) {
    SelectorCancellation *probe = context;
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    cancellation_probe = NULL;
    probe->abandoned = probe->count;
    /* pthread_cond_[timed]wait reacquires its supplied mutex before cancellation
     * cleanup. Keeping its existing held entry is therefore intentional. The
     * request is queued only at capture, never while that wait releases a lock.
     * Unlock abandoned locks solely to permit complete ordinary seed shutdown. */
    while (probe->count)
        if (__real_pthread_mutex_unlock(probe->held[--probe->count]))
            probe->observer_error = true;
    ApplicationFixture *fixture = probe->fixture;
    probe->retirement_left = !probe->returned && fixture->retirement != NULL;
    yd_raft_application_retirement_close(fixture->retirement);
    fixture->retirement = NULL;
    selecting = NULL;
}
static void *selector_cancel_thread(void *context) {
    SelectorCancellation *probe = context;
    ApplicationFixture *fixture = probe->fixture;
    char error[512] = {0};
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) {
        probe->observer_error = true;
        return NULL;
    }
    probe->enabled_entry = previous == PTHREAD_CANCEL_ENABLE;
    cancellation_probe = probe;
    selecting = fixture;
    pthread_cleanup_push(selector_cancel_cleanup, probe);
    (void)pthread_setcancelstate(previous, NULL);
    fixture->outcome = yd_raft_cluster_application_select_outcome(fixture->cluster,
        fixture->image, fixture->timeout, progress, fixture, &fixture->published,
        fixture->retaining ? &fixture->retirement : NULL, error, sizeof(error));
    /* Do not add a testcancel here: absence of delivery at the selector's safe
     * return boundary is itself a failure, rather than a fixture-supplied fix. */
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    probe->returned = true;
    pthread_cleanup_pop(1);
    return NULL;
}

bool __real_yd_test_application_command(ApplicationFixture *, const char *);
bool __wrap_yd_test_application_command(ApplicationFixture *fixture, const char *line) {
    if (!fixture || strcmp(line, "app-pthread-cancel"))
        return __real_yd_test_application_command(fixture, line);
    SelectorCancellation probe = {.fixture = fixture};
    atomic_init(&probe.queued, false);
    pthread_t thread;
    bool valid = fixture->image && !fixture->started && !fixture->retirement;
    fixture->published = false;
    valid = valid && !pthread_create(&thread, NULL, selector_cancel_thread, &probe);
    void *result = NULL;
    if (valid && pthread_join(thread, &result)) valid = false;
    printf("app-pthread-cancel %u %u %u %zu %zu %u %u %u\n", valid,
        probe.enabled_entry, atomic_load(&probe.queued), probe.queued_with_locks,
        probe.abandoned, probe.retirement_left, probe.observer_error ||
            probe.returned || result != PTHREAD_CANCELED, fixture->published);
    return true;
}
