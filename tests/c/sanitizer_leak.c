/* A guest built with AddressSanitizer by hermit-cli/tests/cli.rs, which runs
 * it natively and under hermit to compare what each run's sanitizer does.
 *
 *   leak      loses a 224-byte allocation and exits 0, so only LeakSanitizer's
 *             exit-time check can fail the run.
 *   overflow  reads one byte past an 8-byte allocation, which AddressSanitizer
 *             reports and ends the run with its `exitcode` setting.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Written through a volatile pointer so the compiler keeps each access. */
static char* volatile sink;

static int leak(void) {
  sink = malloc(224);
  memset(sink, 1, 224);
  sink = NULL;
  printf("leaked 224 bytes\n");
  return 0;
}

static int overflow(void) {
  sink = malloc(8);
  memset(sink, 1, 8);
  printf("read past the end: %d\n", sink[8]);
  free(sink);
  return 0;
}

int main(int argc, char** argv) {
  if (argc == 2 && strcmp(argv[1], "leak") == 0) {
    return leak();
  }
  if (argc == 2 && strcmp(argv[1], "overflow") == 0) {
    return overflow();
  }
  fprintf(stderr, "usage: %s leak | overflow\n", argv[0]);
  return 2;
}
