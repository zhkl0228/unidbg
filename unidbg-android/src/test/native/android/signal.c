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

static void sig_act(int signo, siginfo_t *info, void *ucontext) {
    printf("catch signo=%d, info=%p, ucontext=%p\n", signo, info, ucontext);
}

__attribute__((constructor))
static void init() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  for(int i = 1; i <= 64; i++) {
    struct sigaction act;
    struct sigaction old;
    sigemptyset(&act.sa_mask);
    act.sa_sigaction = sig_act;
    act.sa_flags = SA_SIGINFO;
    int ret = sigaction(i, &act, &old);
    int err = ret == -1 ? errno : 0;
    printf("init signal sig=%d, old=%p, err=%d, msg=%s, error=%p\n", i, old.sa_sigaction, err, strerror(err), &errno);
  }
}

int main(int argc, char *argv[]) {
  printf("Start signal test.\n");
  for(int i = 1; i <= 64; i++) {
    sighandler_t old = signal(i, sig);
    printf("main signal sig=%d, old=%p\n", i, old);
  }
  struct sigaction sigaction;
  printf("sizeof(struct sigaction)=%d, sa_handler=%zu, sa_sigaction=%zu\n", (int) sizeof(sigaction), (size_t) &sigaction.sa_handler - (size_t) &sigaction, (size_t) &sigaction.sa_sigaction - (size_t) &sigaction);
  printf("sizeof(struct siginfo)=%d\n", (int) sizeof(struct siginfo));
  int ret = kill(0, SIGALRM);
  printf("kill ret=%d\n", ret);
  return 0;
}
