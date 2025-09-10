#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/sysctl.h>

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

static int GetDarwinSysCtlByNameValue(const char* name) {
  {
    int mib[2];
    int values[2];
    values[0] = 0;
    values[1] = 0;
    size_t size = sizeof(values);
    mib[0] = CTL_UNSPEC;
    mib[1] = 3;
    int r = sysctl(mib, 2, values, &size, (char *) name, strlen(name));
    printf("sysctl name=%s, v0=%d, v1=%d, size=%lu, ret=%d\n", name, values[0], values[1], size, r);
  }
  int enabled;
  size_t enabled_len = sizeof(enabled);
  const int failure = sysctlbyname(name, &enabled, &enabled_len, NULL, 0);
  int ret = failure ? 0 : enabled;
  printf("GetDarwinSysCtlByNameValue %s=0x%x\n", name, ret);
  return ret;
}

static bool GetDarwinSysCtlByName(const char* name) {
  return GetDarwinSysCtlByNameValue(name) != 0;
}

static void testAarch64Info() {
  // Handling Darwin platform through sysctlbyname.
  GetDarwinSysCtlByNameValue("sysctl.proc_native");
  GetDarwinSysCtlByNameValue("machdep.virtual_address_size");
  bool implementer = GetDarwinSysCtlByNameValue("hw.cputype");
  bool variant = GetDarwinSysCtlByNameValue("hw.cpusubtype");
  bool part = GetDarwinSysCtlByNameValue("hw.cpufamily");
  bool revision = GetDarwinSysCtlByNameValue("hw.cpusubfamily");

  bool features_fp = GetDarwinSysCtlByName("hw.optional.floatingpoint");
  bool features_asimd = GetDarwinSysCtlByName("hw.optional.AdvSIMD") ||
                        GetDarwinSysCtlByName("hw.optional.arm.AdvSIMD");
  bool features_aes = GetDarwinSysCtlByName("hw.optional.arm.FEAT_AES");
  bool features_pmull = GetDarwinSysCtlByName("hw.optional.arm.FEAT_PMULL");
  bool features_sha1 = GetDarwinSysCtlByName("hw.optional.arm.FEAT_SHA1");
  bool features_sha2 = GetDarwinSysCtlByName("hw.optional.arm.FEAT_SHA256");
  bool features_crc32 = GetDarwinSysCtlByName("hw.optional.armv8_crc32");
  bool features_atomics = GetDarwinSysCtlByName("hw.optional.arm.FEAT_LSE");
  bool features_fphp = GetDarwinSysCtlByName("hw.optional.arm.FEAT_FP16");
  bool features_asimdhp = GetDarwinSysCtlByName("hw.optional.arm.AdvSIMD_HPFPCvt");
  bool features_asimdrdm = GetDarwinSysCtlByName("hw.optional.arm.FEAT_RDM");
  bool features_jscvt = GetDarwinSysCtlByName("hw.optional.arm.FEAT_JSCVT");
  bool features_fcma = GetDarwinSysCtlByName("hw.optional.arm.FEAT_FCMA");
  bool features_lrcpc = GetDarwinSysCtlByName("hw.optional.arm.FEAT_LRCPC");
  bool features_dcpop = GetDarwinSysCtlByName("hw.optional.arm.FEAT_DPB");
  bool features_sha3 = GetDarwinSysCtlByName("hw.optional.arm.FEAT_SHA3");
  bool features_asimddp = GetDarwinSysCtlByName("hw.optional.arm.FEAT_DotProd");
  bool features_sha512 = GetDarwinSysCtlByName("hw.optional.arm.FEAT_SHA512");
  bool features_asimdfhm = GetDarwinSysCtlByName("hw.optional.arm.FEAT_FHM");
  bool features_dit = GetDarwinSysCtlByName("hw.optional.arm.FEAT_DIT");
  bool features_uscat = GetDarwinSysCtlByName("hw.optional.arm.FEAT_LSE2");
  bool features_flagm = GetDarwinSysCtlByName("hw.optional.arm.FEAT_FlagM");
  bool features_ssbs = GetDarwinSysCtlByName("hw.optional.arm.FEAT_SSBS");
  bool features_sb = GetDarwinSysCtlByName("hw.optional.arm.FEAT_SB");
  bool features_flagm2 = GetDarwinSysCtlByName("hw.optional.arm.FEAT_FlagM2");
  bool features_frint = GetDarwinSysCtlByName("hw.optional.arm.FEAT_FRINTTS");
  bool features_i8mm = GetDarwinSysCtlByName("hw.optional.arm.FEAT_I8MM");
  bool features_bf16 = GetDarwinSysCtlByName("hw.optional.arm.FEAT_BF16");
  bool features_bti = GetDarwinSysCtlByName("hw.optional.arm.FEAT_BTI");
  size_t length = 0;
  if (sysctlbyname("machdep.cpu.brand_string", NULL, &length, NULL, 0) != -1) {
    char *cpu = (char *)malloc(length + 1);
    sysctlbyname("machdep.cpu.brand_string", cpu, &length, NULL, 0);
    printf("cpu=%s\n", cpu);
    free(cpu);
  }
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
    testAarch64Info();

    return 0;
}
