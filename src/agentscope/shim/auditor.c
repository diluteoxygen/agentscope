#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

typedef char *(*real_getenv_t)(const char *name);
typedef char *(*real_secure_getenv_t)(const char *name);

static real_getenv_t real_getenv = NULL;
static real_secure_getenv_t real_secure_getenv = NULL;
static __thread int in_hook = 0;

static void log_env_access(const char *name) {
    if (!name || name[0] == '\0') {
        return;
    }

    /* Prevent recursion */
    if (in_hook) {
        return;
    }
    in_hook = 1;

    const char *log_path = NULL;
    if (real_getenv) {
        log_path = real_getenv("AGENTSCOPE_AUDIT_LOG");
    }

    if (log_path && log_path[0] != '\0') {
        int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (fd >= 0) {
            /* Format: PID:KEY_NAME\n */
            char buf[512];
            pid_t pid = getpid();
            int len = snprintf(buf, sizeof(buf), "%d:%s\n", (int)pid, name);
            if (len > 0) {
                ssize_t written = write(fd, buf, (size_t)len);
                (void)written;
            }
            close(fd);
        }
    }

    in_hook = 0;
}

char *getenv(const char *name) {
    if (!real_getenv) {
        real_getenv = (real_getenv_t)dlsym(RTLD_NEXT, "getenv");
    }

    log_env_access(name);

    if (real_getenv) {
        return real_getenv(name);
    }
    return NULL;
}

char *secure_getenv(const char *name) {
    if (!real_secure_getenv) {
        real_secure_getenv = (real_secure_getenv_t)dlsym(RTLD_NEXT, "secure_getenv");
        if (!real_secure_getenv) {
            real_secure_getenv = (real_secure_getenv_t)dlsym(RTLD_NEXT, "getenv");
        }
    }

    log_env_access(name);

    if (real_secure_getenv) {
        return real_secure_getenv(name);
    }
    return NULL;
}
