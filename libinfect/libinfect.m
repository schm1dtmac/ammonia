//
//  libinfect.c
//  libinfect
//
//  Created by bedtime on 11/19/23.
//


#include "ammonia.h"
#include "frida-gum.h"
#include "envbuf.h"

#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>

#include <ctype.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

void LogToFile(const char *format, ...) {
    // Open the file in append mode
    FILE *file = fopen("/tmp/infect.log", "a");
    
    if (file == NULL) {
        // Failed to open the file
        perror("Error opening file");
        return;
    }

    // Initialize variable arguments
    va_list args;
    va_start(args, format);

    // Use vfprintf to write to the file
    vfprintf(file, format, args);

    // Clean up variable arguments
    va_end(args);

    // Close the file
    fclose(file);
}

int (*SpawnOld)(pid_t * pid, const char * path, const posix_spawn_file_actions_t * ac, const posix_spawnattr_t * ab, char *const __argv[], char *const __envp[]);

bool PathDriver(const char *path) {
    return (strstr(path, "Driver") != NULL);
}

int 
posix_spawnattr_get_darwin_role_np(const posix_spawnattr_t * __restrict attr, 
                                    uint64_t * __restrict darwin_rolep);
#define PRIO_DARWIN_ROLE_UI_FOCAL       0x1     /* On  screen,     focal UI */
#define PRIO_DARWIN_ROLE_UI             0x2     /* On  screen UI,  focal unknown */
#define PRIO_DARWIN_ROLE_UI_NON_FOCAL   0x4     /* On  screen, non-focal UI */

int SpawnNew(pid_t * pid, const char * path, const posix_spawn_file_actions_t * ac, const posix_spawnattr_t * ab, char *const __argv[], char *const __envp[]) {
    char **playground = envbuf_mutcopy((const char **)__envp);

    uint64_t darwin_rolep = 0;
    posix_spawnattr_get_darwin_role_np(ab, &darwin_rolep);

    if (strcmp(path, "/usr/libexec/xpcproxy") == 0) {
        envbuf_setenv(&playground, "DYLD_INSERT_LIBRARIES", SupportFolderP"liblibinfect.dylib");
    } else if (!PathDriver(path)) {
        if (darwin_rolep == PRIO_DARWIN_ROLE_UI_FOCAL || 
            darwin_rolep == PRIO_DARWIN_ROLE_UI || 
            darwin_rolep == PRIO_DARWIN_ROLE_UI_NON_FOCAL) {
            // we are GUI

            char *newlib = SupportFolderP"libopener.dylib";

            int idx = envbuf_find((const char **)playground, "DYLD_INSERT_LIBRARIES");
            if (idx >= 0) {
                const char *old = playground[idx] + strlen("DYLD_INSERT_LIBRARIES=");
                char *combined = NULL;
                if (asprintf(&combined, "%s:%s", old, newlib) != -1) {
                    envbuf_setenv(&playground, "DYLD_INSERT_LIBRARIES", combined);
                    free(combined);
                }
            } else {
                envbuf_setenv(&playground, "DYLD_INSERT_LIBRARIES", newlib);
            }

            int k = SpawnOld(pid, path, ac, ab, __argv, (char *const *)playground);
            return k;
        }
    }
    

    int k = SpawnOld(pid, path, ac, ab, __argv, (char *const *)playground);
    return k;
}

int SpawnPNew(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t * ac, const posix_spawnattr_t *restrict ab, char *const *restrict argv, char *const *restrict envp) {
    return SpawnNew(pid, path, ac, ab, argv, envp);
}

void __attribute__((constructor)) Infect(void) {
    gum_init_embedded();
    GumInterceptor *interceptor = gum_interceptor_obtain();
    gum_interceptor_begin_transaction (interceptor);
    gum_interceptor_replace (interceptor, (gpointer)gum_module_find_export_by_name(NULL, "posix_spawn"), (gpointer)SpawnNew, NULL, (gpointer *)&SpawnOld);
    gum_interceptor_replace (interceptor, (gpointer)gum_module_find_export_by_name(NULL, "posix_spawnp"), (gpointer)SpawnPNew, NULL, (gpointer *)(NULL));
    gum_interceptor_end_transaction (interceptor);
}
