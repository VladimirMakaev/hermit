/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

/*
 * Prints every number a process sees for its parent, process group and
 * session, by each surface Linux offers: getppid, getpgrp, getpgid, getsid,
 * /proc/self/stat, /proc/thread-self/stat, /proc/<pid>/stat (fields 1 and 4
 * to 8) and /proc/self/status and /proc/<pid>/status (Tgid, Pid, PPid,
 * NStgid, NSpid). It prints them for itself (the run's root process), for a
 * child, for the root's files read by that child (another process's), and
 * for an orphan, the child's child after the child exits.
 *
 * In a PID namespace the root's parent, group and session are outside the
 * namespace and read 0, and an orphan's parent is the namespace's init, 1
 * (task_tgid_nr_ns, task_pgrp_nr_ns, task_session_nr_ns and pid_nr_ns in
 * fs/proc/array.c and kernel/sys.c). Hermit's test runs it with
 * `--no-namespace --pid-base`, where the kernel numbers by the host's PID
 * namespace, and requires those values, the same bytes in every run.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char* what) {
  printf("FAIL %s: %s\n", what, strerror(errno));
  exit(1);
}

static void read_file(const char* path, char* buf, size_t size) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    die(path);
  }
  size_t used = 0;
  for (;;) {
    ssize_t n = read(fd, buf + used, size - 1 - used);
    if (n < 0) {
      die(path);
    }
    if (n == 0 || used + (size_t)n == size - 1) {
      used += (size_t)n;
      break;
    }
    used += (size_t)n;
  }
  buf[used] = '\0';
  close(fd);
}

/* Fields 1 and 4 to 8 of a stat file. */
static void print_stat(const char* who, const char* label, const char* path) {
  char buf[4096];
  read_file(path, buf, sizeof buf);
  char* end = strrchr(buf, ')');
  if (end == NULL) {
    errno = EINVAL;
    die(path);
  }
  char state;
  int ppid, pgrp, session, tty_nr, tpgid;
  if (sscanf(end + 2, "%c %d %d %d %d %d", &state, &ppid, &pgrp, &session,
             &tty_nr, &tpgid) != 6) {
    errno = EINVAL;
    die(path);
  }
  printf("%s %s pid=%d ppid=%d pgrp=%d session=%d tpgid=%d\n", who, label,
         atoi(buf), ppid, pgrp, session, tpgid);
}

/* The process numbers of a status file. */
static void print_status(const char* who, const char* label, const char* path) {
  static const char* const labels[] = {"Tgid:", "Pid:", "PPid:", "NStgid:",
                                       "NSpid:"};
  char buf[8192];
  read_file(path, buf, sizeof buf);
  printf("%s %s", who, label);
  for (size_t i = 0; i < sizeof labels / sizeof labels[0]; i++) {
    char* line = buf;
    for (;;) {
      if (strncmp(line, labels[i], strlen(labels[i])) == 0) {
        char* value = line + strlen(labels[i]);
        char* eol = strchr(value, '\n');
        if (eol != NULL) {
          *eol = '\0';
        }
        while (*value == '\t' || *value == ' ') {
          value++;
        }
        printf(" %s%s", labels[i], value);
        if (eol != NULL) {
          *eol = '\n';
        }
        break;
      }
      line = strchr(line, '\n');
      if (line == NULL) {
        printf(" %s?", labels[i]);
        break;
      }
      line++;
    }
  }
  printf("\n");
}

/* Every surface of the calling process. */
static void print_own(const char* who) {
  char path[64];
  printf("%s getppid=%d getpgrp=%d getpgid=%d getsid=%d\n", who, getppid(),
         getpgrp(), getpgid(0), getsid(0));
  print_stat(who, "self-stat", "/proc/self/stat");
  print_stat(who, "thread-self-stat", "/proc/thread-self/stat");
  snprintf(path, sizeof path, "/proc/%d/stat", getpid());
  print_stat(who, "pid-stat", path);
  print_status(who, "self-status", "/proc/self/status");
  snprintf(path, sizeof path, "/proc/%d/status", getpid());
  print_status(who, "pid-status", path);
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  pid_t root = getpid();
  print_own("root");
  printf("root getpgid-by-pid=%d getsid-by-pid=%d\n", getpgid(root),
         getsid(root));

  /* `go` tells the orphan its parent is gone: the root writes it once it has
   * reaped the child, after the kernel reparented the orphan (exit_notify
   * runs before a child can be reaped). `done` is held by the child and the
   * orphan and read to EOF by the root, so every line comes before the
   * root's last. */
  int go[2], done[2];
  if (pipe2(go, O_CLOEXEC) != 0 || pipe2(done, O_CLOEXEC) != 0) {
    die("pipe2");
  }
  pid_t child = fork();
  if (child < 0) {
    die("fork");
  }
  if (child == 0) {
    char path[64];
    close(go[1]);
    close(done[0]);
    print_own("child");
    snprintf(path, sizeof path, "/proc/%d/stat", root);
    print_stat("child", "root-stat", path);
    snprintf(path, sizeof path, "/proc/%d/status", root);
    print_status("child", "root-status", path);
    printf("child root-getpgid=%d root-getsid=%d\n", getpgid(root),
           getsid(root));
    pid_t orphan = fork();
    if (orphan < 0) {
      die("fork");
    }
    if (orphan == 0) {
      char byte;
      if (read(go[0], &byte, 1) != 1) {
        die("read go");
      }
      print_own("orphan");
      _exit(0);
    }
    _exit(0);
  }
  close(go[0]);
  close(done[1]);
  int status;
  if (waitpid(child, &status, 0) != child) {
    die("waitpid");
  }
  printf("root child-status=%d\n", WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  if (write(go[1], "x", 1) != 1) {
    die("write go");
  }
  char byte;
  while (read(done[0], &byte, 1) > 0) {
  }
  printf("root done\n");
  return 0;
}
