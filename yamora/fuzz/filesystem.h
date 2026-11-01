#ifndef YAMORA_FUZZ_FILESYSTEM_H
#define YAMORA_FUZZ_FILESYSTEM_H

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *yd_fuzz_scratch_root(void)
{
    static char root[PATH_MAX];
    static bool checked = false;
    if (checked) {
        return root[0] == '\0' ? NULL : root;
    }
    checked = true;
    const char *repository = getenv("ANDROMEDA_REPOSITORY");
    const char *selected_python = getenv("CI_PYTHON");
    char python[PATH_MAX];
    int length = -1;
    if (repository != NULL) {
        length = selected_python != NULL && selected_python[0] != '\0'
            ? snprintf(python, sizeof(python), "%s", selected_python)
            : snprintf(python, sizeof(python), "%s/.venv/bin/python", repository);
    }
    if (length <= 0 || length >= PATH_MAX) {
        fputs("fuzz scratch requires an inherited managed repository environment\n", stderr);
        return NULL;
    }
    int descriptors[2];
    if (pipe(descriptors) != 0) {
        return NULL;
    }
    pid_t child = fork();
    if (child == 0) {
        close(descriptors[0]);
        if (dup2(descriptors[1], STDOUT_FILENO) < 0) {
            _exit(127);
        }
        close(descriptors[1]);
        execl(python, python, "-c",
            "import sys;sys.path.insert(0,sys.argv[1]);from tools.shared.scratch import storage_root;print(storage_root())",
            repository, (char *)NULL);
        _exit(127);
    }
    close(descriptors[1]);
    size_t used = 0;
    while (child > 0 && used < sizeof(root) - 1) {
        ssize_t count = read(descriptors[0], root + used, sizeof(root) - used - 1);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            break;
        }
        used += (size_t)count;
    }
    close(descriptors[0]);
    int status = 0;
    pid_t waited;
    do {
        waited = child > 0 ? waitpid(child, &status, 0) : -1;
    } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0 ||
        used < 2 || used == sizeof(root) - 1 || root[0] != '/' || root[used - 1] != '\n') {
        root[0] = '\0';
        return NULL;
    }
    root[used - 1] = '\0';
    if (strchr(root, '\n') != NULL || strchr(root, '\r') != NULL) {
        root[0] = '\0';
        return NULL;
    }
    return root;
}

static bool yd_fuzz_data_dir(char path[PATH_MAX], const char *label)
{
    const char *temporary_root = yd_fuzz_scratch_root();
    if (temporary_root == NULL) {
        return false;
    }
    int length = snprintf(path, PATH_MAX, "%s/yamora-%s-XXXXXX", temporary_root, label);
    return length > 0 && length < PATH_MAX && mkdtemp(path) != NULL;
}

static void yd_fuzz_remove_data_dir(const char *path)
{
    DIR *root = opendir(path);
    if (root == NULL) {
        return;
    }
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(root);
        if (entry == NULL) {
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char child[PATH_MAX];
        int length = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (length <= 0 || (size_t)length >= sizeof(child)) {
            continue;
        }
        struct stat status;
        if (lstat(child, &status) != 0) {
            continue;
        }
        if (!S_ISDIR(status.st_mode)) {
            (void)unlink(child);
            continue;
        }
        DIR *collection = opendir(child);
        if (collection == NULL) {
            continue;
        }
        for (;;) {
            struct dirent *document = readdir(collection);
            if (document == NULL) {
                break;
            }
            if (strcmp(document->d_name, ".") == 0 || strcmp(document->d_name, "..") == 0) {
                continue;
            }
            char document_path[PATH_MAX];
            length = snprintf(
                document_path,
                sizeof(document_path),
                "%s/%s",
                child,
                document->d_name
            );
            if (length > 0 && (size_t)length < sizeof(document_path)) {
                (void)unlink(document_path);
            }
        }
        (void)closedir(collection);
        (void)rmdir(child);
    }
    (void)closedir(root);
    (void)rmdir(path);
}

#endif
