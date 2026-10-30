/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * The memory layout a process's /proc/<pid>/stat shows: startcode (field
 * 26), endcode (27), startstack (28), kstkesp and kstkeip (29, 30), and
 * startdata, enddata, startbrk, argstart, argend, envstart and envend
 * (45-51). Linux prints the mm's values to a permitted reader
 * (fs/proc/array.c do_task_stat) and 0 for kstkesp and kstkeip unless the
 * task is exiting or dumping core.
 *
 * Bionic's pthread_getattr_np for the main thread reads startstack from
 * /proc/self/stat and aborts when no /proc/self/maps line holds it, so an
 * ART program cannot start where startstack is 0. The "self" mode runs that
 * search first. Every check compares the fields with what the process sees
 * of its own layout, so the output is the same natively, with or without
 * address-space randomization, and under Hermit.
 *
 * Usage: proc_stat_memory_layout MODE
 *
 *   self    /proc/self/stat: bionic's main-stack search finds the [stack]
 *           mapping; argc sits at startstack and argv right after it; main
 *           is inside the code range, an initialized global inside the data
 *           range; the program break starts at or after the data and at or
 *           before sbrk(0); the argument and environment strings span
 *           exactly argstart..argend and envstart..envend; kstkesp and
 *           kstkeip are 0.
 *   thread  a second thread reads /proc/thread-self/stat,
 *           /proc/self/task/<tid>/stat and /proc/self/stat: each shows the
 *           process's layout (one mm).
 *   child   a forked child that has not exec'd shows its parent's layout
 *           (fork copies the mm); once it has exited (a zombie, observed
 *           with waitid(WNOWAIT)), every layout field is 0 (no mm).
 *   nondumpable
 *           "self" after prctl(PR_SET_DUMPABLE, 0): the process's own
 *           thread group may always read its layout.
 *
 * Prints one "MODE CHECK ok" line per check, or "MODE CHECK FAIL ..." with
 * the values, and exits 1 after any failure.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

/* An initialized global, which the linker puts in the data segment. */
int initialized_global = 42;

static const char* mode;
static int failures;

/* The /proc/<pid>/stat fields this test reads, by Linux's field number. */
enum {
  F_STARTCODE = 26,
  F_ENDCODE = 27,
  F_STARTSTACK = 28,
  F_KSTKESP = 29,
  F_KSTKEIP = 30,
  F_STARTDATA = 45,
  F_ENDDATA = 46,
  F_STARTBRK = 47,
  F_ARGSTART = 48,
  F_ARGEND = 49,
  F_ENVSTART = 50,
  F_ENVEND = 51,
};

static const int layout_fields[] = {
    F_STARTCODE,
    F_ENDCODE,
    F_STARTSTACK,
    F_KSTKESP,
    F_KSTKEIP,
    F_STARTDATA,
    F_ENDDATA,
    F_STARTBRK,
    F_ARGSTART,
    F_ARGEND,
    F_ENVSTART,
    F_ENVEND,
};
#define LAYOUT_FIELDS (sizeof(layout_fields) / sizeof(layout_fields[0]))

/* Fields 1..52 of one stat line; field[2], the name, is not kept. */
struct stat_line {
  uintmax_t field[53];
};

static void check(const char* name, int ok, const char* detail) {
  if (ok) {
    printf("%s %s ok\n", mode, name);
  } else {
    printf("%s %s FAIL %s\n", mode, name, detail);
    failures++;
  }
}

static void read_file(const char* path, char* buffer, size_t size) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    fprintf(stderr, "open %s: %s\n", path, strerror(errno));
    exit(2);
  }
  size_t total = 0;
  for (;;) {
    ssize_t got = read(fd, buffer + total, size - 1 - total);
    if (got < 0) {
      fprintf(stderr, "read %s: %s\n", path, strerror(errno));
      exit(2);
    }
    if (got == 0 || total + (size_t)got == size - 1) {
      total += (size_t)got;
      break;
    }
    total += (size_t)got;
  }
  buffer[total] = '\0';
  close(fd);
}

/*
 * Parse a stat line as bionic does: the name may hold spaces and ')', so the
 * fields start after the last ')'. Field 3 (the state) is a letter.
 */
static void read_stat(const char* path, struct stat_line* stat) {
  char line[4096];
  read_file(path, line, sizeof(line));
  memset(stat, 0, sizeof(*stat));
  char* end_of_comm = strrchr(line, ')');
  if (end_of_comm == NULL) {
    fprintf(stderr, "%s: no ')' in %s\n", path, line);
    exit(2);
  }
  char* cursor = end_of_comm + 1;
  int field = 3;
  char* token;
  char* save = NULL;
  for (token = strtok_r(cursor, " \n", &save); token != NULL && field <= 52;
       token = strtok_r(NULL, " \n", &save), field++) {
    if (field == 3) {
      continue;
    }
    stat->field[field] = strtoumax(token, NULL, 10);
  }
  if (field != 53) {
    fprintf(stderr, "%s: %d fields\n", path, field - 1);
    exit(2);
  }
}

/*
 * Bionic's __find_main_stack_limits (libc/bionic/pthread_attr.cpp): the
 * /proc/self/maps line whose range holds startstack, ends included. Returns
 * whether one does, and copies its name.
 */
static int find_main_stack(uintptr_t startstack, char* name, size_t size) {
  FILE* maps = fopen("/proc/self/maps", "re");
  if (maps == NULL) {
    fprintf(stderr, "fopen /proc/self/maps: %s\n", strerror(errno));
    exit(2);
  }
  char line[4096];
  while (fgets(line, sizeof(line), maps) != NULL) {
    uintptr_t lo, hi;
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &lo, &hi) == 2 &&
        lo <= startstack && startstack <= hi) {
      char* newline = strchr(line, '\n');
      if (newline != NULL) {
        *newline = '\0';
      }
      /* The name is the sixth column, after the inode. */
      char* column = line;
      for (int skip = 0; skip < 5 && column != NULL; skip++) {
        column = strchr(column, ' ');
        while (column != NULL && *column == ' ') {
          column++;
        }
      }
      snprintf(name, size, "%s", column == NULL ? "" : column);
      fclose(maps);
      return 1;
    }
  }
  fclose(maps);
  return 0;
}

static void self_mode(int argc, char** argv) {
  struct stat_line stat;
  read_stat("/proc/self/stat", &stat);
  char detail[512];
  uintptr_t startstack = (uintptr_t)stat.field[F_STARTSTACK];

  char name[256] = "";
  int found = find_main_stack(startstack, name, sizeof(name));
  snprintf(
      detail,
      sizeof(detail),
      "startstack %#" PRIxPTR " found %d in \"%s\"",
      startstack,
      found,
      name);
  check(
      "bionic-main-stack-search",
      found && strcmp(name, "[stack]") == 0,
      detail);

  /* create_elf_tables puts argc at bprm->p, mm->start_stack, then argv. */
  snprintf(
      detail,
      sizeof(detail),
      "startstack %#" PRIxPTR " argv %p",
      startstack,
      (void*)argv);
  check(
      "argc-at-startstack",
      startstack != 0 && *(long*)startstack == argc &&
          (uintptr_t)argv == startstack + sizeof(long),
      detail);

  uintptr_t main_address = (uintptr_t)&self_mode;
  snprintf(
      detail,
      sizeof(detail),
      "code %#jx..%#jx function %#" PRIxPTR,
      stat.field[F_STARTCODE],
      stat.field[F_ENDCODE],
      main_address);
  check(
      "code-range",
      stat.field[F_STARTCODE] <= main_address &&
          main_address < stat.field[F_ENDCODE],
      detail);

  uintptr_t data_address = (uintptr_t)&initialized_global;
  snprintf(
      detail,
      sizeof(detail),
      "data %#jx..%#jx global %#" PRIxPTR,
      stat.field[F_STARTDATA],
      stat.field[F_ENDDATA],
      data_address);
  check(
      "data-range",
      stat.field[F_STARTDATA] <= data_address &&
          data_address < stat.field[F_ENDDATA],
      detail);

  uintptr_t current_break = (uintptr_t)sbrk(0);
  long page = sysconf(_SC_PAGESIZE);
  snprintf(
      detail,
      sizeof(detail),
      "enddata %#jx startbrk %#jx sbrk(0) %#" PRIxPTR,
      stat.field[F_ENDDATA],
      stat.field[F_STARTBRK],
      current_break);
  check(
      "program-break",
      stat.field[F_STARTBRK] != 0 &&
          stat.field[F_ENDDATA] <= stat.field[F_STARTBRK] &&
          stat.field[F_STARTBRK] <= current_break &&
          stat.field[F_STARTBRK] % (uintmax_t)page == 0,
      detail);

  uintptr_t arg_end = (uintptr_t)argv[argc - 1] + strlen(argv[argc - 1]) + 1;
  snprintf(
      detail,
      sizeof(detail),
      "args %#jx..%#jx strings %p..%#" PRIxPTR,
      stat.field[F_ARGSTART],
      stat.field[F_ARGEND],
      (void*)argv[0],
      arg_end);
  check(
      "argument-strings",
      stat.field[F_ARGSTART] == (uintptr_t)argv[0] &&
          stat.field[F_ARGEND] == arg_end,
      detail);

  /* The environment strings follow the arguments' (create_elf_tables). */
  char** envp = argv + argc + 1;
  uintptr_t env_start = (uintptr_t)arg_end;
  uintptr_t env_end = env_start;
  size_t count = 0;
  while (envp[count] != NULL) {
    count++;
  }
  if (count > 0) {
    env_start = (uintptr_t)envp[0];
    env_end = (uintptr_t)envp[count - 1] + strlen(envp[count - 1]) + 1;
  }
  snprintf(
      detail,
      sizeof(detail),
      "env %#jx..%#jx strings %#" PRIxPTR "..%#" PRIxPTR " (%zu)",
      stat.field[F_ENVSTART],
      stat.field[F_ENVEND],
      env_start,
      env_end,
      count);
  check(
      "environment-strings",
      stat.field[F_ENVSTART] == env_start && stat.field[F_ENVEND] == env_end &&
          stat.field[F_ENVSTART] == stat.field[F_ARGEND] &&
          envp == (count > 0 ? environ : envp),
      detail);

  snprintf(
      detail,
      sizeof(detail),
      "kstkesp %#jx kstkeip %#jx",
      stat.field[F_KSTKESP],
      stat.field[F_KSTKEIP]);
  check(
      "no-kernel-stack-registers",
      stat.field[F_KSTKESP] == 0 && stat.field[F_KSTKEIP] == 0,
      detail);
}

/*
 * Whether `other` shows the layout `expected` does; names the first field
 * that differs.
 */
static int same_layout(
    const struct stat_line* expected,
    const struct stat_line* other,
    char* detail,
    size_t size) {
  for (size_t index = 0; index < LAYOUT_FIELDS; index++) {
    int field = layout_fields[index];
    if (expected->field[field] != other->field[field]) {
      snprintf(
          detail,
          size,
          "field %d %#jx, expected %#jx",
          field,
          other->field[field],
          expected->field[field]);
      return 0;
    }
  }
  snprintf(detail, size, "same");
  return 1;
}

static struct stat_line process_layout;

static void* thread_reads(void* unused) {
  (void)unused;
  char detail[256];
  char path[64];
  struct stat_line stat;

  read_stat("/proc/thread-self/stat", &stat);
  int same = same_layout(&process_layout, &stat, detail, sizeof(detail));
  check("thread-self-stat", same, detail);

  snprintf(
      path,
      sizeof(path),
      "/proc/self/task/%ld/stat",
      (long)syscall(SYS_gettid));
  read_stat(path, &stat);
  same = same_layout(&process_layout, &stat, detail, sizeof(detail));
  check("task-tid-stat", same, detail);

  read_stat("/proc/self/stat", &stat);
  same = same_layout(&process_layout, &stat, detail, sizeof(detail));
  check("self-stat-from-thread", same, detail);
  return NULL;
}

static void thread_mode(void) {
  read_stat("/proc/self/stat", &process_layout);
  char detail[64];
  snprintf(
      detail,
      sizeof(detail),
      "startstack %#jx",
      process_layout.field[F_STARTSTACK]);
  check("process-startstack", process_layout.field[F_STARTSTACK] != 0, detail);
  pthread_t thread;
  if (pthread_create(&thread, NULL, thread_reads, NULL) != 0) {
    fprintf(stderr, "pthread_create failed\n");
    exit(2);
  }
  pthread_join(thread, NULL);
}

static void child_mode(void) {
  struct stat_line own;
  read_stat("/proc/self/stat", &own);
  int to_child[2];
  if (pipe(to_child) != 0) {
    perror("pipe");
    exit(2);
  }
  fflush(stdout);
  pid_t child = fork();
  if (child < 0) {
    perror("fork");
    exit(2);
  }
  if (child == 0) {
    char byte;
    close(to_child[1]);
    /* Wait, alive and unchanged, until the parent has read the stat. */
    ssize_t got = read(to_child[0], &byte, 1);
    _exit(got == 1 ? 0 : 3);
  }
  close(to_child[0]);

  char path[64];
  char detail[256];
  struct stat_line stat;
  snprintf(path, sizeof(path), "/proc/%d/stat", (int)child);
  read_stat(path, &stat);
  int same = same_layout(&own, &stat, detail, sizeof(detail));
  if (same && own.field[F_STARTSTACK] == 0) {
    snprintf(detail, sizeof(detail), "both show startstack 0");
    same = 0;
  }
  check("live-child-has-parents-layout", same, detail);

  if (write(to_child[1], "x", 1) != 1) {
    perror("write");
    exit(2);
  }
  siginfo_t info;
  memset(&info, 0, sizeof(info));
  if (waitid(P_PID, child, &info, WEXITED | WNOWAIT) != 0) {
    perror("waitid");
    exit(2);
  }
  read_stat(path, &stat);
  struct stat_line none;
  memset(&none, 0, sizeof(none));
  same = same_layout(&none, &stat, detail, sizeof(detail));
  check("zombie-child-has-no-layout", same, detail);

  int status;
  if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
      WEXITSTATUS(status) != 0) {
    fprintf(stderr, "child did not exit 0: %#x\n", status);
    exit(2);
  }
}

int main(int argc, char** argv) {
  mode = argc > 1 ? argv[1] : "self";
  if (strcmp(mode, "self") == 0) {
    self_mode(argc, argv);
  } else if (strcmp(mode, "thread") == 0) {
    thread_mode();
  } else if (strcmp(mode, "child") == 0) {
    child_mode();
  } else if (strcmp(mode, "nondumpable") == 0) {
    /*
     * A reader in the process's own thread group is always permitted
     * (__ptrace_may_access), so the layout shows though the process is not
     * dumpable.
     */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
      perror("prctl");
      return 2;
    }
    self_mode(argc, argv);
  } else {
    fprintf(stderr, "unknown mode %s\n", mode);
    return 2;
  }
  return failures == 0 ? 0 : 1;
}
