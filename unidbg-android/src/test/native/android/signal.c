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
  for(int i = 1; i <= SIGUNUSED; i++) {
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

static void *start_routine(void *arg) {
  printf("Call start_routine arg=%p, errno=%p\n", arg, &errno);
  return (void *) &init;
}

int main(int argc, char *argv[]) {
  pthread_t main = pthread_self();
  pid_t tid = gettid();
  printf("Start signal test, main=%ld, tid=%d.\n", main, tid);
  for(int i = 1; i <= SIGUNUSED; i++) {
    sighandler_t old = signal(i, sig);
    printf("main signal sig=%d, old=%p\n", i, old);
  }
  struct sigaction sigaction;
  printf("sizeof(struct sigaction)=%d, sa_handler=%zu, sa_sigaction=%zu\n", (int) sizeof(sigaction), (size_t) &sigaction.sa_handler - (size_t) &sigaction, (size_t) &sigaction.sa_sigaction - (size_t) &sigaction);
  printf("sizeof(struct siginfo)=%d\n", (int) sizeof(struct siginfo));
  int ret = kill(0, SIGALRM);
  printf("kill ret=%d\n", ret);
  ret = raise(SIGTERM);
  printf("raise ret=%d, sizeof(pid_t)=%zu\n", ret, sizeof(pid_t));
  ret = pthread_kill(main, SIGTSTP);
  printf("pthread_kill ret=%d\n", ret);
  pthread_t thread = 0;
  ret = pthread_create(&thread, NULL, start_routine, &sigaction);
  void *value = NULL;
  int join_ret = pthread_join(thread, &value);
  printf("pthread_join ret=%d, join_ret=%d, thread=%ld, value=%p\n", ret, join_ret, thread, value);
  return 0;
}
