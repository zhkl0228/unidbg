#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include "test.h"

static uint64_t gettid() {
  uint64_t tid;
  pthread_threadid_np(NULL, &tid);
  return tid;
}

static void sig(int signo) {
  uint64_t tid = gettid();
  printf("catch signo=%d, tid=%llu\n", signo, tid);
}

static void sig_act(int signo, siginfo_t *info, void *ucontext) {
  uint64_t tid = gettid();
  printf("catch signo=%d, info=%p, ucontext=%p, tid=%llu\n", signo, info, ucontext, tid);
}

__attribute__((constructor))
static void init() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  for(int i = 1; i <= 31; i++) {
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

static void test_kqueue() {
  uint64_t tid = gettid();
  struct kevent64_s kev = {
    .ident = 1,
    .filter = EVFILT_USER,
    .flags = EV_ADD|EV_CLEAR,
  };
  guardid_t guard = (uintptr_t)&kev;
  int kq = guarded_kqueue_np(&guard, GUARD_CLOSE | GUARD_DUP);
  int ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
  char buf[256];
  hex(buf, (void *)&kev, sizeof(kev));
  printf("test_kqueue first kq=%d, ret=%d, tid=%llu, kev=%s\n", kq, ret, tid, buf);
  struct kevent64_s trigger = {
    .ident = 1,
    .filter = EVFILT_USER,
    .fflags = NOTE_TRIGGER,
  };
  ret = kevent64(kq, &trigger, 1, NULL, 0, 0, NULL);
  hex(buf, (void *)&trigger, sizeof(trigger));
  printf("test_kqueue trigger kq=%d, ret=%d, tid=%llu, trigger=%s\n", kq, ret, tid, buf);
  ret = kevent64(kq, NULL, 0, &kev, 1, 0, NULL);
  hex(buf, (void *)&kev, sizeof(kev));
  printf("test_kqueue second kq=%d, ret=%d, tid=%llu, kev=%s\n", kq, ret, tid, buf);
}

static void *start_routine(void *arg) {
  uint64_t tid = gettid();
  printf("Call start_routine arg=%p, tid=%llu, errno=%p\n", arg, tid, &errno);
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
  test_kqueue();
  return (void *) &init;
}

typedef struct thread_context {
  volatile int status;
  pthread_cond_t threadCond;
  pthread_mutex_t threadLock;
} *t_thread_context;

static void *join_routine(void *arg) {
  t_thread_context ctx = (t_thread_context) arg;
  ctx->status = 1;
  pthread_cond_broadcast(&ctx->threadCond);
  printf("test_pthread start_routine ctx=%p\n", ctx);
  void *ret = (void *)&join_routine;
  while (ctx->status != 2) {
    pthread_cond_wait(&ctx->threadCond, &ctx->threadLock);
  }
  printf("test_pthread start_routine arg=%p, ret=%p\n", arg, ret);
  ctx->status = 3;
  pthread_cond_broadcast(&ctx->threadCond);
  return ret;
}

static void test_pthread_join() {
  pthread_t thread = 0;
  struct thread_context context;
  context.status = 0;
  pthread_cond_init(&context.threadCond, NULL);
  pthread_mutex_init(&context.threadLock, NULL);
  void *arg = &context;
  pthread_attr_t threadAttr;
  pthread_attr_init(&threadAttr);
  pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_DETACHED);
  int ret = pthread_create(&thread, &threadAttr, join_routine, arg);
  pthread_attr_destroy(&threadAttr);

  while (context.status != 1) {
    pthread_cond_wait(&context.threadCond, &context.threadLock);
  }
  printf("test_pthread first arg=%p, ret=%d, thread=%p\n", arg, ret, thread);
  context.status = 2;
  pthread_cond_broadcast(&context.threadCond);

  while (context.status != 3) {
    pthread_cond_wait(&context.threadCond, &context.threadLock);
  }

  pthread_cond_destroy(&context.threadCond);
  pthread_mutex_destroy(&context.threadLock);
  printf("test_pthread second arg=%p, ret=%d, thread=%p\n", arg, ret, thread);
}

int main(int argc, char *argv[]) {
    printf("Start kqueue test: sizeof(pid_t)=%zu\n", sizeof(pid_t));

    pthread_t main = pthread_self();
    uint64_t tid = gettid();
    printf("Start signal test, main=%p, pid=%d, tid=%llu.\n", (void *) main, getpid(), tid);
    for(int i = 1; i <= 31; i++) {
      sig_t old = signal(i, sig);
      printf("main signal sig=%d, old=%p\n", i, old);
    }
    struct sigaction sigaction;
    printf("sizeof(struct sigaction)=%d, sa_handler=%zu, sa_sigaction=%zu\n", (int) sizeof(sigaction), (size_t) &sigaction.sa_handler - (size_t) &sigaction, (size_t) &sigaction.sa_sigaction - (size_t) &sigaction);
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

    test_pthread_join();

    return 0;
}
