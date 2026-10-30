/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Two threads each load and unload a shared library ten times. Every dlopen
 * and dlclose passes the dynamic loader's debugger hooks, where gdb keeps
 * breakpoints of its own for as long as it is attached (its shared-library
 * event breakpoint, or the loader's probes), so a session that only
 * continues still stops the guest there dozens of times.
 *
 * Each thread notes every load in a shared log, which is printed at the end:
 * the order of the loads shows how the threads were scheduled.
 */

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>

#define LOADS 10

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static char load_log[2 * LOADS + 1];
static int logged;

static void* load_and_unload(void* arg) {
  const char* name = arg;
  for (int i = 0; i < LOADS; i++) {
    void* lib = dlopen("libm.so.6", RTLD_NOW);
    if (lib == NULL) {
      fprintf(stderr, "dlopen: %s\n", dlerror());
      return NULL;
    }
    pthread_mutex_lock(&log_lock);
    load_log[logged++] = name[0];
    pthread_mutex_unlock(&log_lock);
    dlclose(lib);
  }
  return arg;
}

int main(void) {
  pthread_t thread;
  if (pthread_create(&thread, NULL, load_and_unload, "t") != 0) {
    return 1;
  }
  void* main_done = load_and_unload("m");
  void* thread_done = NULL;
  if (pthread_join(thread, &thread_done) != 0) {
    return 1;
  }
  if (main_done == NULL || thread_done == NULL) {
    return 1;
  }
  printf("loads: %s\n", load_log);
  return 0;
}
