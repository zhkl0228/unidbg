#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <stdio.h>

#include "test.h"

static void sig(int signo) {
  pid_t tid = gettid();
  printf("catch signo=%d, tid=%d\n", signo, tid);
}

static void sig_act(int signo, siginfo_t *info, void *ucontext) {
  pid_t tid = gettid();
  printf("catch signo=%d, info=%p, ucontext=%p, tid=%d\n", signo, info, ucontext, tid);
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

static void do_sigprocmask() {
  sigset_t set, old;
  sigemptyset(&set);
  sigemptyset(&old);
  sigaddset(&set, SIGALRM);
  sigaddset(&set, SIGTSTP);
  int ret = pthread_sigmask(SIG_SETMASK, &set, &old);
  char set_buf[256];
  char old_buf[256];
  memset(set_buf, 0, 256);
  memset(old_buf, 0, 256);
  hex(set_buf, &set, sizeof(set));
  hex(old_buf, &old, sizeof(old));
  printf("do_sigprocmask ret=%d, set=%s, old=%s\n", ret, set_buf, old_buf);
}

static void do_sigwait() {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGTSTP);
  sigaddset(&set, SIGALRM);
  int sig = 0;
  int ret = sigwait(&set, &sig);
  printf("do_sigwait ret=%d, sig=%d\n", ret, sig);
}

static void *start_routine(void *arg) {
  pid_t tid = gettid();
  printf("Call start_routine arg=%p, tid=%d, errno=%p\n", arg, tid, &errno);
  do_sigprocmask();
  raise(SIGTSTP);
  do_sigwait();
  raise(SIGTSTP);
  sigset_t set;
  sigemptyset(&set);
  int ret = sigpending(&set);
  char buf[256];
  memset(buf, 0, 256);
  hex(buf, &set, sizeof(set));
  printf("sigpending ret=%d, set=%s, size=%zu, errno=%p\n", ret, buf, sizeof(set), &errno);
  FILE *fp = fopen("/failed", "r");
  printf("open fp=%p, errno=%d, msg=%s\n", fp, errno, strerror(errno));
  return (void *) &init;
}

int main(int argc, char *argv[]) {
  pthread_t main = pthread_self();
  pid_t tid = gettid();
  printf("Start signal test, main=%p, pid=%d, tid=%d.\n", (void *) main, getpid(), tid);
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
  pthread_t thread = 0;
  ret = pthread_create(&thread, NULL, start_routine, &sigaction);
  pthread_kill(thread, SIGTSTP);
  pthread_kill(thread, SIGALRM);
  printf("pthread_kill ret=%d\n", ret);
  void *value = NULL;
  int join_ret = pthread_join(thread, &value);
  printf("pthread_join ret=%d, join_ret=%d, thread=%p, value=%p\n", ret, join_ret, (void *)thread, value);
  return 0;
}
