/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// A lost wakeup. Each round starts a signaller that publishes `ready` and
// signals the condition variable without taking the mutex. A signal sent
// after the waiter has checked `ready` but before pthread_cond_wait has
// registered it wakes nobody, and the waiter then waits forever. Whether a
// round loses its wakeup depends only on where the scheduler preempts the
// waiter, so under a chaos seed the program either deadlocks at one round,
// having printed the rounds before it, or finishes every round.
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int ready;

static void* signaller(void* arg) {
  (void)arg;
  __atomic_store_n(&ready, 1, __ATOMIC_RELAXED);
  pthread_cond_signal(&cond);
  return NULL;
}

int main(int argc, char** argv) {
  int rounds = argc > 1 ? atoi(argv[1]) : 200;
  for (int round = 0; round < rounds; round++) {
    pthread_t thread;
    __atomic_store_n(&ready, 0, __ATOMIC_RELAXED);
    if (pthread_create(&thread, NULL, signaller, NULL) != 0) {
      perror("pthread_create");
      return 2;
    }
    pthread_mutex_lock(&lock);
    while (!__atomic_load_n(&ready, __ATOMIC_RELAXED)) {
      // From the check of `ready` until the wait registers, a signal is
      // lost; the spin widens that window.
      for (volatile int spin = 0; spin < 50; spin++) {
      }
      pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);
    pthread_join(thread, NULL);
    printf("round %d\n", round);
    fflush(stdout);
  }
  printf("all %d rounds finished\n", rounds);
  return 0;
}
