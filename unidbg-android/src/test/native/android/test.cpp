#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/statfs.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/system_properties.h>

#include <iostream>
#include <exception>

#include "test.h"

static int sdk_int = 0;

static void test_stat() {
  struct stat st;
  printf("st_nlink=0x%lx, st_blocks=0x%lx, st_rdev=0x%lx, st_uid=0x%lx, st_mtime=0x%lx, size=%lu\n", (long) &st.st_nlink - (long) &st, (long) &st.st_blocks - (long) &st, (long) &st.st_rdev - (long) &st, (long) &st.st_uid - (long) &st, (long) &st.st_mtime - (long) &st, (unsigned long) sizeof(st));
}

static void test_dirent() {
  struct dirent dt;
  fprintf(stdout, "dirent size=%lu\n", (unsigned long) sizeof(dt));
}

static void test_ioctl() {
  struct ifconf ifc;
  struct ifreq ibuf[256];
  ifc.ifc_len = sizeof ibuf;
  ifc.ifc_buf = (caddr_t)ibuf;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  ioctl(fd, SIOCGIFCONF, (char *)&ifc);

  printf("sizeof ifconf=%lu, ifreq=%lu\n", (unsigned long) sizeof(struct ifconf), (unsigned long) sizeof(struct ifreq));
  int i = 0;
  for (; i < ifc.ifc_len / sizeof(*ifc.ifc_ifcu.ifcu_req); ++i) {
    printf("ioctl %d  %zu  %s %d\n", i, strlen(ibuf[i].ifr_name), ibuf[i].ifr_name, ibuf[i].ifr_addr.sa_family);
  }
  close(fd);
}

// 3.不可靠信号的丢失
static void signal_handler(int signo) {
    printf("received a signal: %d\n", signo);
}

static void test_signal() {
    pid_t pid;
    sigset_t set;
    sigset_t oset;

    sigemptyset(&set);          //清空
    sigaddset(&set, SIGINT);          //添加2号信号
    sigaddset(&set, SIGRTMIN);         //添加34号信号
    sigprocmask(SIG_SETMASK, &set, &oset);     //将这个集合设置为这个进程的阻塞信号集

    //绑定信号
    signal(SIGINT, signal_handler);
    signal(SIGRTMIN, signal_handler);

    sigprocmask(SIG_SETMASK, &oset, NULL); //解除绑定
}

static void handler(int signo, siginfo_t *resdata, void *unknowp) {
    printf("signo=%d\n", signo);
    printf("return data :%d\n", resdata->si_value.sival_int);
}

static void test_signalaction() {
    pid_t pid = fork();
    if(pid == -1) {
        perror("create fork");
        return;
    } else if(pid == 0) { // 子进程
        sleep(1);
        //发送信号
        int i = 5;
        while(i--) {
            kill(getppid(), SIGINT);
            printf("send signal: %d success!\n", SIGINT);
            kill(getppid(), SIGRTMIN);
            printf("send signal: %d success!\n", SIGRTMIN);
        }
    } else {
        struct sigaction act;
        //初始化sa_mask
        sigemptyset(&act.sa_mask);
        act.sa_handler = signal_handler;
        act.sa_sigaction = handler;
        //一旦使用了sa_sigaction属性，那么必须设置sa_flags属性的值为SA_SIGINFO
        act.sa_flags = SA_SIGINFO;

        //注册信号
        sigaction(SIGINT, &act, NULL);
        sigaction(SIGRTMIN, &act, NULL);
    }
}

__attribute__((constructor))
void init() {
  char sdk[PROP_VALUE_MAX];
  __system_property_get("ro.build.version.sdk", sdk);
  sdk_int = atoi(sdk);
  printf("constructor sdk=%d\n", sdk_int);
}

static void test_backtrace() {
}

static void test_statfs() {
  struct statfs stb;
  int ret = statfs("/data/app", &stb);
  char buf[1024];
  hex(buf, &stb, sizeof(stb));
  printf("test_statfs size=%d, ret=%d, hex=%s\n", (int) sizeof(stb), ret, buf);
}

static float sFloat = 0.0023942017f;

static float* float_func() {
  return &sFloat;
}

static void test_float() {
  float *f = float_func();
  void *ptr = f;
  unsigned int *ip = (unsigned int *) ptr;
  printf("test_float size=%zu, ip=0x%x\n", sizeof(float), *ip);
}

static void test_jni_float() {
}

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  fprintf(stderr, "Start test, stdin=%p, stdout=%p, stderr=%p, size=%lu\n", stdin, stdout, stderr, (unsigned long) sizeof(*stdout));
  test_stat();
  test_dirent();
  test_ioctl();
  if(sdk_int > 19) {
    test_signal();
    test_signalaction();
  }
  test_backtrace();
  test_statfs();
  test_float();
  test_jni_float();
  char sdk[PROP_VALUE_MAX];
  __system_property_get("ro.build.version.sdk", sdk);
  printf("Press any key to exit: cmp=%d\n", strcmp("23", sdk));
  getchar();
  return 0;
}
