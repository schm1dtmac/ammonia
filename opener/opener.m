//
//  opener.c
//  opener
//
//  Created by whisper on 9/2/23.
//
#include <Foundation/Foundation.h>
#include "opener.h"
#include <mach/task_policy.h>
#include <string.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <libproc.h>

const char *GetExePath(void) {
    uint32_t bufsize = 0;
    _NSGetExecutablePath(NULL, &bufsize);
    char *executablePath = malloc(bufsize);
    _NSGetExecutablePath(&executablePath[0], &bufsize);
    return executablePath;
}

void Open(void * interceptor) { 
    DIR *dr;
    struct dirent *en;
    dr = opendir(SupportFolderP "tweaks/"); // Open the directory
    if (dr) {
        while ((en = readdir(dr)) != NULL) {
            if (en->d_type == DT_REG) {
                char full_path[PATH_MAX];
                snprintf(full_path, sizeof(full_path), "%stweaks/%s", SupportFolderP, en->d_name);

                // Construct paths for whitelist and blacklist files
                char whitelist_file[PATH_MAX];
                snprintf(whitelist_file, sizeof(whitelist_file), "%stweaks/%s.whitelist", SupportFolderP, en->d_name);

                char blacklist_file[PATH_MAX];
                snprintf(blacklist_file, sizeof(blacklist_file), "%stweaks/%s.blacklist", SupportFolderP, en->d_name);

                const char *exe_path = GetExePath();
                bool should_load = false;

                // Priority 1: whitelist
                FILE *whitelist_fp = fopen(whitelist_file, "r");
                if (whitelist_fp) {
                    char process_name[256];
                    while (fgets(process_name, sizeof(process_name), whitelist_fp) != NULL) {
                        size_t len = strlen(process_name);
                        if (len > 0 && process_name[len - 1] == '\n') {
                            process_name[len - 1] = '\0';
                        }

                        if (strstr(exe_path, process_name) != NULL) {
                            should_load = true;
                            break;
                        }
                    }
                    fclose(whitelist_fp);

                    if (!should_load) {
                        syslog(LOG_INFO, "Process %s is not whitelisted for %s.", exe_path, en->d_name);
                        goto cleanup;
                    }
                } else {
                    // Priority 2: blacklist
                    FILE *blacklist_fp = fopen(blacklist_file, "r");
                    if (blacklist_fp) {
                        should_load = true;
                        char process_name[256];
                        while (fgets(process_name, sizeof(process_name), blacklist_fp) != NULL) {
                            size_t len = strlen(process_name);
                            if (len > 0 && process_name[len - 1] == '\n') {
                                process_name[len - 1] = '\0';
                            }

                            if (strstr(exe_path, process_name) != NULL) {
                                should_load = false;
                                syslog(LOG_INFO, "Process %s is blacklisted for %s.", exe_path, en->d_name);
                                break;
                            }
                        }
                        fclose(blacklist_fp);
                        if (!should_load) {
                            goto cleanup;
                        }
                    } else {
                        // Neither whitelist nor blacklist exists — skip
                        goto cleanup;
                    }
                }

                // Load the dylib
                void *handle = dlopen(full_path, RTLD_NOW | RTLD_GLOBAL);
                if (handle == NULL) {
                    syslog(LOG_ERR, "Error loading %s: %s", full_path, dlerror());
                } else {
                    void (*LoadFunction)(void *) = dlsym(handle, "LoadFunction");
                    if (LoadFunction != NULL) {
                        LoadFunction(interceptor);
                    }
                }

            cleanup:
                continue;
            }
        }
        closedir(dr);
    } else {
        syslog(LOG_ERR, "Error opening tweaks directory.");
    }
    closelog();
}

int IsForegroundProcess()
{
    task_t currentTask = mach_task_self();
    task_category_policy_data_t category_policy;
    mach_msg_type_number_t task_info_count = TASK_CATEGORY_POLICY_COUNT;
    boolean_t get_default = FALSE;
    kern_return_t result = task_policy_get(currentTask, TASK_CATEGORY_POLICY, (task_policy_t)&category_policy, &task_info_count, &get_default);
    
    if (result != KERN_SUCCESS)
    {
        fprintf(stderr, "Error getting task category policy: %s\n", mach_error_string(result));
        return -1; // or handle the error appropriately
    }

    return !(category_policy.role & TASK_BACKGROUND_APPLICATION) ||
           !(category_policy.role & TASK_FOREGROUND_APPLICATION) ||
    //       !(category_policy.role & TASK_UNSPECIFIED) || // a gamble
           !(category_policy.role & TASK_DEFAULT_APPLICATION);
}

static bool gum_loaded = false;

typedef void (*GumInitEmbeddedFunc_t)(void);
typedef void *(*GumInterceptorObtainFunc_t)(void);
typedef void (*GumInterceptorBeginTransactionFunc_t)(void *interceptor);
typedef void (*GumInterceptorEndTransactionFunc_t)(void *interceptor);
typedef bool (*GumInterceptorReplaceFunc_t)(void *interceptor,
                                            void *target,
                                            void *replacement,
                                            void *user_data,
                                            void **out_original);
typedef bool (*GumInterceptorRevertFunc_t)(void *interceptor,
                                           void *target);


void __attribute__((constructor)) ctor_main(void) {
    // Make frida interceptor availible to tweaks
    void *hooking = dlopen("/private/var/ammonia/core/fridagum.dylib", RTLD_NOW | RTLD_GLOBAL);
    GumInitEmbeddedFunc_t GumInitEmbeddedFunc = dlsym(hooking, "gum_init_embedded");
    GumInterceptorObtainFunc_t GumInterceptorObtainFunc = dlsym(hooking, "gum_interceptor_obtain");
    if (!gum_loaded) {
        GumInitEmbeddedFunc();
        gum_loaded = true;
    }

    Open(GumInterceptorObtainFunc());
}