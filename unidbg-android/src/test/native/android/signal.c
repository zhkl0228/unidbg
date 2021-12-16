#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>

#include "test.h"

static void sig(int signo) {
    printf("catch signo=%d\n", signo);
}

__attribute__((constructor))
static void init() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  for(int i = 1; i <= 64; i++) {
    sighandler_t old = signal(i, sig);
    int err = old == SIG_ERR ? errno : 0;
    printf("init signal sig=%d, old=%p, error=%d, msg=%s\n", i, old, err, strerror(err));
  }
}

int main(int argc, char *argv[]) {
  printf("Start signal test.\n");
  for(int i = 1; i <= 64; i++) {
    sighandler_t old = signal(i, sig);
    printf("main signal sig=%d, old=%p\n", i, old);
  }
  printf("sizeof(struct sigaction)=%d\n", (int) sizeof(struct sigaction));
  int ret = kill(0, SIGALRM);
  printf("kill ret=%d\n", ret);
  return 0;
}
