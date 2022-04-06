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
#include <pthread.h>
#include <sys/system_properties.h>

#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <iostream>
#include <exception>

#include <sched.h>
#include <link.h>

#include "test.h"

static int sdk_int = 0;

typedef struct thread_context {
  int status;
  pthread_cond_t threadCond;
  pthread_mutex_t threadLock;
} *t_thread_context;

static void *start_routine(void *arg) {
  t_thread_context ctx = (t_thread_context) arg;
  ctx->status = 1;
  pthread_cond_broadcast(&ctx->threadCond);
  printf("test_pthread start_routine ctx=%p\n", ctx);
  void *ret = &sdk_int;
  while (ctx->status != 2) {
    pthread_cond_wait(&ctx->threadCond, &ctx->threadLock);
  }
  printf("test_pthread start_routine arg=%p, ret=%p\n", arg, ret);
  ctx->status = 3;
  pthread_cond_broadcast(&ctx->threadCond);
  return ret;
}

static void test_pthread() {
  pthread_t thread = 0;
  struct thread_context context;
  context.status = 0;
  pthread_cond_init(&context.threadCond, NULL);
  pthread_mutex_init(&context.threadLock, NULL);
  void *arg = &context;
  pthread_attr_t threadAttr;
  pthread_attr_init(&threadAttr);
  pthread_attr_setdetachstate(&threadAttr, PTHREAD_CREATE_DETACHED);
  int ret = pthread_create(&thread, &threadAttr, start_routine, arg);
  pthread_attr_destroy(&threadAttr);

  while (context.status != 1) {
    pthread_cond_wait(&context.threadCond, &context.threadLock);
  }
  printf("test_pthread first arg=%p, ret=%d, thread=0x%lx\n", arg, ret, thread);
  context.status = 2;
  pthread_cond_broadcast(&context.threadCond);

  while (context.status != 3) {
    pthread_cond_wait(&context.threadCond, &context.threadLock);
  }

  pthread_cond_destroy(&context.threadCond);
  pthread_mutex_destroy(&context.threadLock);
  printf("test_pthread second arg=%p, ret=%d, thread=0x%lx\n", arg, ret, thread);
}

static void sig_alrm(int signo) {
    printf("after sigwait, catch SIGALRM, signo=%d\n", signo);
    fflush(stdout);
    return;
}

static void sig_init(int signo) {
    printf("catch SIGINT, signo=%d\n", signo);
    fflush(stdout);
    return;
}

static void test_sigwait() {
  sigset_t set;
  int sig;
  sigemptyset(&set);
  sigaddset(&set, SIGALRM);
  char buf[16384];
  hex(buf, &set, sizeof(set));

  pthread_sigmask(SIG_SETMASK, &set, NULL); // 阻塞 SIGALRM 信号
  signal(SIGALRM, sig_alrm);
  signal(SIGINT, sig_init);
  sigwait(&set, &sig); // sigwait只是从未决队列中删除该信号，并不改变信号掩码。也就是，当sigwait函数返回，它监听的信号依旧被阻塞。
  if(sig == SIGALRM) {
    printf("sigwait, receive signal SIGALRM\n");
  }
  sigdelset(&set, SIGALRM);
  pthread_sigmask(SIG_SETMASK, &set, NULL);

  printf("test_sigwait set=%s\n", buf);
}

#define INFINITY_LIFE_TIME      0xFFFFFFFFU
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static void test_netlink() {
  static __u32 seq = 0;
  struct rtattr *rta;
  int fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
  if(fd == -1) {
    printf("test_netlink code=%d, msg=%s\n", errno, strerror(errno));
    return;
  }
  struct {
    struct nlmsghdr n;
    struct ifaddrmsg r;
    int pad[4];
  } req;
  memset(&req, 0, sizeof(req));
  req.n.nlmsg_len = sizeof(req);
  req.n.nlmsg_type = RTM_GETADDR;
  req.n.nlmsg_flags = NLM_F_MATCH | NLM_F_REQUEST;
  req.n.nlmsg_pid = 0;
  req.n.nlmsg_seq = seq;
  req.r.ifa_family = AF_UNSPEC;

  /* Fill up all the attributes for the rtnetlink header. The code is pretty easy
         to understand. The lenght is very important. We use 16 to signify the ipv6
         address. If the user chooses to use AF_INET (ipv4) the length has to be
         RTA_LENGTH(4) */
  rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.n.nlmsg_len));
  rta->rta_len = RTA_LENGTH(4);

  char buf[16384];
  hex(buf, &req, sizeof(req));
  int ret = sendto(fd, (void *)&req, sizeof(req), 0, NULL, 0);
  printf("test_netlink fd=%d, sizeof(req)=%zu, buf=%s, ret=%d\n", fd, sizeof(req), buf, ret);

  memset(buf, 0, sizeof(buf));
  int status = recv(fd, buf, sizeof(buf), 0);
  if (status < 0) {
      perror("test_netlink");
      return;
  }
  if(status == 0) {
      printf("test_netlink EOF\n");
      return;
  }
  char str[16384];
  hex(str, buf, status);
  printf("test_netlink status=%d, buf=%s\n", status, str);

  struct nlmsghdr *nlmp;
  struct ifaddrmsg *rtmp;
  struct rtattr *rtatp;
  int rtattrlen;
  struct in_addr *inp;
  struct ifa_cacheinfo *cache_info;

  /* Typically the message is stored in buf, so we need to parse the message to *
          * get the required data for our display. */

  next_nlmp:
      for(nlmp = (struct nlmsghdr *)buf; status > sizeof(*nlmp);){
          int len = nlmp->nlmsg_len;
          int req_len = len - sizeof(*nlmp);

          if (req_len<0 || len>status) {
              printf("test_netlink error\n");
              return;
          }

          if (!NLMSG_OK(nlmp, status)) {
              printf("test_netlink NLMSG not OK\n");
              return;
          }

          rtmp = (struct ifaddrmsg *)NLMSG_DATA(nlmp);
          rtatp = (struct rtattr *)IFA_RTA(rtmp);

          /* Start displaying the index of the interface */

          int ctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
          struct ifreq ifr;
          memset(&ifr, 0, sizeof(ifr));
          ifr.ifr_ifindex = rtmp->ifa_index;
          ioctl(ctl_sock, SIOCGIFNAME, &ifr);
          ioctl(ctl_sock, SIOCGIFFLAGS, &ifr);
          printf("Index Of Iface: %d, name=%s, flags=0x%x\n", rtmp->ifa_index, ifr.ifr_name, ifr.ifr_flags);
          close(ctl_sock);

          rtattrlen = IFA_PAYLOAD(nlmp);

          for (; RTA_OK(rtatp, rtattrlen); rtatp = RTA_NEXT(rtatp, rtattrlen)) {

              /* Here we hit the fist chunk of the message. Time to validate the    *
                   * the type. For more info on the different types see man(7) rtnetlink*
                   * The table below is taken from man pages.                           *
                   * Attributes                                                         *
                   * rta_type        value type             description                 *
                   * -------------------------------------------------------------      *
                   * IFA_UNSPEC      -                      unspecified.                *
                   * IFA_ADDRESS     raw protocol address   interface address           *
                   * IFA_LOCAL       raw protocol address   local address               *
                   * IFA_LABEL       asciiz string          name of the interface       *
                   * IFA_BROADCAST   raw protocol address   broadcast address.          *
                   * IFA_ANYCAST     raw protocol address   anycast address             *
                   * IFA_CACHEINFO   struct ifa_cacheinfo   Address information.        */

              if(rtatp->rta_type == IFA_LABEL){
                  const char *label = (const char *)RTA_DATA(rtatp);
                  printf("  label: %s\n", label);
              }

              if(rtatp->rta_type == IFA_CACHEINFO){
                  cache_info = (struct ifa_cacheinfo *)RTA_DATA(rtatp);
                  if (cache_info->ifa_valid == INFINITY_LIFE_TIME)
                      printf("  valid_lft forever\n");
                  else
                      printf("  valid_lft %usec\n", cache_info->ifa_valid);

                  if (cache_info->ifa_prefered == INFINITY_LIFE_TIME)
                      printf("  preferred_lft forever\n");
                  else
                      printf("  preferred_lft %usec\n",cache_info->ifa_prefered);
              }

              /* NOTE: All the commented code below can be used as it is for ipv4 table */

              if(rtatp->rta_type == IFA_ADDRESS){
                  inp = (struct in_addr *)RTA_DATA(rtatp);
                  //  in6p = (struct in6_addr *)RTA_DATA(rtatp);
                  //  printf("addr0: " NIP6_FMT "\n",NIP6(*in6p));
                  printf("  addr0: %u.%u.%u.%u\n",NIPQUAD(*inp));
              }

              if(rtatp->rta_type == IFA_LOCAL){
                  inp = (struct in_addr *)RTA_DATA(rtatp);
                  //  in6p = (struct in6_addr *)RTA_DATA(rtatp);
                  //  printf("addr1: " NIP6_FMT "\n",NIP6(*in6p));
                  printf("  addr1: %u.%u.%u.%u\n",NIPQUAD(*inp));
              }

              if(rtatp->rta_type == IFA_BROADCAST){
                  inp = (struct in_addr *)RTA_DATA(rtatp);
                  //  in6p = (struct in6_addr *)RTA_DATA(rtatp);
                  //  printf("bcataddr: " NIP6_FMT "\n",NIP6(*in6p));
                  printf("  Bcast addr: %u.%u.%u.%u\n",NIPQUAD(*inp));
              }

              if(rtatp->rta_type == IFA_ANYCAST){
                  inp = (struct in_addr *)RTA_DATA(rtatp);
                  //  in6p = (struct in6_addr *)RTA_DATA(rtatp);
                  //  printf("anycastaddr: "NIP6_FMT"\n",NIP6(*in6p));
                  printf("  anycast addr: %u.%u.%u.%u\n",NIPQUAD(*inp));
              }

          }
          status -= NLMSG_ALIGN(len);
          nlmp = (struct nlmsghdr*)((char*)nlmp + NLMSG_ALIGN(len));

      }

  status = recv(fd, buf, sizeof(buf), 0);
  printf("test_netlink status=%d\n", status);
  if(status > 0) {
    goto next_nlmp;
  }
  close(fd);
}

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

    char buf[1000];
    hex(buf, &set, sizeof(set));
    printf("test_signal set=%s\n", buf);

    //绑定信号
    signal(SIGINT, signal_handler);
    signal(SIGRTMIN, signal_handler);

    sigprocmask(SIG_SETMASK, &oset, NULL); //解除绑定
}

static void handler(int signo, siginfo_t *info, void *ucontext) {
    printf("signo=%d, info=%p, ucontext=%p\n", signo, info, ucontext);
    printf("return data: %d, si_signo=%d\n", info->si_value.sival_int, info->si_signo);
}

static void test_signalaction() {
    pid_t pid = fork();
    printf("test_signalaction pid=%d\n", pid);
    if(pid == -1) {
        perror("create fork");
        return;
    } else if(pid == 0) { // 子进程
        sleep(1);
        //发送信号
        kill(getppid(), SIGINT);
        printf("send signal: %d success!\n", SIGINT);
        kill(getppid(), SIGRTMIN);
        printf("send signal: %d success!\n", SIGRTMIN);
        exit(0);
    } else {
        struct sigaction act;
        //初始化sa_mask
        sigemptyset(&act.sa_mask);
        act.sa_sigaction = handler;
        //一旦使用了sa_sigaction属性，那么必须设置sa_flags属性的值为SA_SIGINFO
        act.sa_flags = SA_SIGINFO;

        //注册信号
        sigaction(SIGINT, &act, NULL);
        sigaction(SIGRTMIN, &act, NULL);

        //发送信号
        kill(0, SIGINT);
        printf("send signal: %d success!\n", SIGINT);
        raise(SIGRTMIN);
        printf("raise signal: %d success!\n", SIGRTMIN);
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

static void test_sched() {
    int cpus = 0;
    int  i = 0;
    cpu_set_t mask;
    cpu_set_t get;
    int pid = gettid();

    cpus = sysconf(_SC_NPROCESSORS_ONLN);
    printf("cpus: %d, pid: %d\n", cpus, pid);

    CPU_ZERO(&get);
    if (sched_getaffinity(pid, sizeof(get), &get) != 0) {
        printf("Get CPU affinity failure, ERROR: %s\n", strerror(errno));
    } else {
        for(int i = 0; i < cpus; i++) {
            if(CPU_ISSET(i, &get)) {
                printf("Running processor : %d\n", i);
            }
        }
        char buf[1024];
        hex(buf, &get, sizeof(get));
        printf("Get CPU affinity success: buf=%s\n", buf);
    }

    CPU_ZERO(&mask);
    CPU_SET(cpus - 1, &mask);
    if (sched_setaffinity(pid, sizeof(mask), &mask) != 0) {
        printf("Set CPU affinity failure, ERROR: %s\n", strerror(errno));
    } else {
        char buf[1024];
        hex(buf, &mask, sizeof(mask));
        printf("Set CPU affinity success: buf=%s\n", buf);
    }

    CPU_ZERO(&get);
    if (sched_getaffinity(pid, sizeof(get), &get) != 0) {
        printf("Get CPU affinity failure, ERROR: %s\n", strerror(errno));
    } else {
        for(int i = 0; i < cpus; i++) {
            if(CPU_ISSET(i, &get)) {
                printf("Running processor : %d\n", i);
            }
        }
        char buf[1024];
        hex(buf, &get, sizeof(get));
        printf("Get CPU affinity success: buf=%s\n", buf);
    }
}

static int dl_iterate_phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
   const char *type;
   int p_type;

   printf("dl_iterate_phdr_callback Name: \"%s\" (%d segments) => %p\n", info->dlpi_name,
              info->dlpi_phnum, info->dlpi_name);

   if(!info->dlpi_name) {
     return 0;
   }

   for (int j = 0; j < info->dlpi_phnum; j++) {
       p_type = info->dlpi_phdr[j].p_type;
       type =  (p_type == PT_LOAD) ? "PT_LOAD" :
               (p_type == PT_DYNAMIC) ? "PT_DYNAMIC" :
               (p_type == PT_INTERP) ? "PT_INTERP" :
               (p_type == PT_NOTE) ? "PT_NOTE" :
               (p_type == PT_INTERP) ? "PT_INTERP" :
               (p_type == PT_PHDR) ? "PT_PHDR" :
               (p_type == PT_TLS) ? "PT_TLS" :
               (p_type == PT_GNU_EH_FRAME) ? "PT_GNU_EH_FRAME" :
               (p_type == PT_GNU_STACK) ? "PT_GNU_STACK" :
               (p_type == PT_GNU_RELRO) ? "PT_GNU_RELRO" : NULL;

       printf("    %2d: [%14p; memsz:%7jx] flags: %#jx; ", j,
               (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr),
               (uintmax_t) info->dlpi_phdr[j].p_memsz,
               (uintmax_t) info->dlpi_phdr[j].p_flags);
       if (type != NULL)
           printf("%s\n", type);
       else
           printf("[other (%#x)]\n", p_type);
   }

   return strcmp("libnative.so", info->dlpi_name) == 0 ? size : 0;
}

static void test_dl_iterate_phdr() {
  int ret = dl_iterate_phdr(dl_iterate_phdr_callback, NULL);
  printf("test_dl_iterate_phdr sizeof(dl_phdr_info)=0x%x, sizeof(Phdr)=0x%x, ret=%d\n", (unsigned int) sizeof(struct dl_phdr_info), (unsigned int) sizeof(ElfW(Phdr)), ret);
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
    test_sigwait();
  }
  test_backtrace();
  test_statfs();
  test_sched();
  test_float();
  test_jni_float();
  char sdk[PROP_VALUE_MAX];
  __system_property_get("ro.build.version.sdk", sdk);
  test_dl_iterate_phdr();
  test_netlink();
  test_pthread();
  printf("Press any key to exit: cmp=%d\n", strcmp("23", sdk));
  getchar();
  return 0;
}
