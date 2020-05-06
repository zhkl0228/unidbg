#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

#define RTM_IFINFO	0xe

static void test_printf() {
  char buf[0x40];
  memset(buf, 0, 0x40);
  snprintf(buf, 0x40, "snprintf: %p\n", buf);
  printf("printf[%p] if_nametoindex=%d, test=%s", buf, if_nametoindex("en0"), buf);
  fprintf(stdout, "ENOTDIR=0x%x, O_WRONLY=0x%x, O_RDWR=0x%x, O_NONBLOCK=0x%x, O_APPEND=0x%x, O_CREAT=0x%x, O_DIRECTORY=0x%x\n", ENOTDIR, O_WRONLY, O_RDWR, O_NONBLOCK, O_APPEND, O_CREAT, O_DIRECTORY);
  printf("test_printf sizeof(sigaction)=%lu\n", sizeof(struct	sigaction));
}

static void test_sysctl_CTL_UNSPEC() {
  int mib[2];
  int values[14];
  size_t size = sizeof(values);

  char *name = "hw.memsize";

  mib[0] = CTL_UNSPEC;
  mib[1] = 3;
  int ret = sysctl(mib, 2, values, &size, name, strlen(name));
  printf("test_sysctl_CTL_UNSPEC ret=%d, ctl=%d, type=%d, size=%zu\n", ret, values[0], values[1], size);
}

static void test_sysctl_CTL_NET() {
  size_t buffSize = 0;
  int					mib[6] = {CTL_NET, AF_ROUTE, 0, 0, NET_RT_IFLIST, 0 };
  int ret = sysctl(mib, 6, NULL, &buffSize, NULL, 0);
  char *buf = malloc(buffSize);
  ret = sysctl(mib, 6, buf, &buffSize, NULL, 0);

  struct if_msghdr	*ifm = (struct if_msghdr *) buf;
  char *end = buf + buffSize;

  while((char*)ifm < end) {
    if(ifm->ifm_type == RTM_IFINFO) {
      struct sockaddr_dl	*sdl = (struct sockaddr_dl *) (ifm + 1);
      char *name = malloc(sdl->sdl_nlen + 1);
      memcpy(name, sdl->sdl_data, sdl->sdl_nlen);
      name[sdl->sdl_nlen] = 0;
      char *mac = malloc(128);
      int index = 0;
      for(int i = 0; i < sdl->sdl_alen; i++) {
        index += sprintf(&mac[index], "%x:", sdl->sdl_data[sdl->sdl_nlen+i] & 0xff);
      }
      mac[index-1] = 0;
      printf("test_sysctl_CTL_NET ifm_msglen=%hu, ifm=%p, name=%s, mac=%s, sizeof_if_msghdr=%lu, sizeof_sockaddr_dl=%lu\n", ifm->ifm_msglen, ifm, name, mac, sizeof(struct if_msghdr), sizeof(struct sockaddr_dl));
      printf("test_sysctl_CTL_NET ifm_version=%d, ifm_type=%d, ifm_addrs=%d, ifm_flags=%d, ifm_index=%d, sdl_family=%d\n", ifm->ifm_version, ifm->ifm_type, ifm->ifm_addrs, ifm->ifm_flags, ifm->ifm_index, sdl->sdl_family);
      printf("test_sysctl_CTL_NET ifi_type=%d, ifi_typelen=%d, ifi_physical=%d, sdl_len=%d, sdl_index=%d, sdl_type=%d, sdl_slen=%d\n", ifm->ifm_data.ifi_type, ifm->ifm_data.ifi_typelen, ifm->ifm_data.ifi_physical, sdl->sdl_len, sdl->sdl_index, sdl->sdl_type, sdl->sdl_slen);
      free(mac);
      free(name);
    }
    ifm = (struct if_msghdr *)  ((char*)ifm + ifm->ifm_msglen);
  }

  free(buf);
}

static void test_sysctl_KERN_USRSTACK() {
  int mib[2];
  void *stack = NULL;
  size_t size = sizeof(stack);

  mib[0] = CTL_KERN;
  mib[1] = KERN_USRSTACK;
  int ret = sysctl(mib, 2, &stack, &size, NULL, 0);
  printf("sysctl_KERN_USRSTACK ret=%d, stack=%p, mib=%p, offset=0x%lx\n", ret, stack, mib, ((long) stack - (long) mib));
}

static void test_sysctl_HW_MACHINE() {
  size_t size;
  sysctlbyname("hw.machine", NULL, &size, NULL, 0);
  char *machine = malloc(size);
  sysctlbyname("hw.machine", machine, &size, NULL, 0);
  printf("test_sysctl_HW_MACHINE machine=%s\n", machine);
  free(machine);
}

static void test_sysctl_HW_MODEL() {
  size_t size;
  sysctlbyname("hw.model", NULL, &size, NULL, 0);
  char *model = malloc(size);
  sysctlbyname("hw.model", model, &size, NULL, 0);
  printf("test_sysctl_HW_MODEL model=%s\n", model);
  free(model);
}

static void test_sysctl_KERN_VERSION() {
  size_t size;
  sysctlbyname("kern.version", NULL, &size, NULL, 0);
  char *version = malloc(size);
  sysctlbyname("kern.version", version, &size, NULL, 0);
  printf("test_sysctl_KERN_VERSION version=%s\n", version);
  free(version);
}

static void test_sysctl_KERN_BOOTTIME() {
  size_t size;
  sysctlbyname("kern.boottime", NULL, &size, NULL, 0);
  char *boot_time = malloc(size);
  sysctlbyname("kern.boottime", boot_time, &size, NULL, 0);
  uint32_t timestamp = 0;
  memcpy(&timestamp, boot_time, sizeof(uint32_t));
  printf("test_sysctl_KERN_BOOTTIME boot_time=%u, size=%zu\n", timestamp, size);
  free(boot_time);
}

static void test_sysctl_KERN_PROC() {
  int mib[4];
  struct kinfo_proc info;
  size_t size = sizeof(struct kinfo_proc);

  pid_t pid = getpid();
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PID;
  mib[3] = pid;

  int ret = sysctl(mib, 4, &info, &size, 0, 0);

  struct kinfo_proc *p_info = &info;
  printf("sysctl_KERN_PROC ret=%d, pid=%d, p_realtimer=0x%lx, e_spare=0x%lx\n", ret, pid, ((long) &p_info->kp_proc.p_realtimer - (long) p_info), ((long) &p_info->kp_eproc.e_spare - (long) &p_info->kp_eproc));
}

#define PROC_PIDT_SHORTBSDINFO		13
#define PROC_PIDT_SHORTBSDINFO_SIZE	(sizeof(struct proc_bsdshortinfo))

struct proc_bsdshortinfo {
        uint32_t                pbsi_pid;		/* process id */
        uint32_t                pbsi_ppid;		/* process parent id */
        uint32_t                pbsi_pgid;		/* process perp id */
	uint32_t                pbsi_status;		/* p_stat value, SZOMB, SRUN, etc */
	char                    pbsi_comm[MAXCOMLEN];	/* upto 16 characters of process name */
	uint32_t                pbsi_flags;              /* 64bit; emulated etc */
        uid_t                   pbsi_uid;		/* current uid on process */
        gid_t                   pbsi_gid;		/* current gid on process */
        uid_t                   pbsi_ruid;		/* current ruid on process */
        gid_t                   pbsi_rgid;		/* current tgid on process */
        uid_t                   pbsi_svuid;		/* current svuid on process */
        gid_t                   pbsi_svgid;		/* current svgid on process */
        uint32_t                pbsi_rfu;		/* reserved for future use*/
};

extern int proc_pidinfo(int pid, int flavor, uint64_t arg,  void *buffer, int buffersize);

static void test_proc_pidinfo() {
  struct proc_bsdshortinfo bsdinfo;

  pid_t pid = getpid();
  int ret = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 1, &bsdinfo, sizeof(bsdinfo));
  printf("proc_pidinfo ret=%d, pid=%d, size=%lu, pbsi_comm=%s, pbsi_flags=0x%x, pbsi_ppid=%d\n", ret, pid, sizeof(bsdinfo), bsdinfo.pbsi_comm, bsdinfo.pbsi_flags, bsdinfo.pbsi_ppid);
}

static void test_pthread() {
  char name[64];
  sprintf(name, "thread: %p", name);
  pthread_setname_np(name);
  memset(name, 0, 64);
  pthread_t thread = pthread_self();
  pthread_getname_np(thread, name, sizeof(name));
  printf("pthread[%p] name=%s\n", thread, name);
}

static void test_file() {
  const char *file = "/tmp/test_file.txt";
  int fd = open(file, O_RDWR | O_CREAT);
  if(fd == -1) {
    printf("open file errno=%d, msg=%s\n", errno, strerror(errno));
  } else {
    close(fd);
    FILE *fp = fopen(file, "r");
    fseek(fp, 0, SEEK_END);
    struct stat statbuf;
    stat(file, &statbuf);
    char buf[256];
    printf("stat st_size=0x%lx, st_blocks=0x%lx, st_blksize=0x%lx, st_gid=0x%lx, st_flags=0x%lx\n", (long)&statbuf.st_size - (long) &statbuf, (long)&statbuf.st_blocks - (long) &statbuf, (long)&statbuf.st_blksize - (long) &statbuf, (long)&statbuf.st_gid - (long) &statbuf, (long)&statbuf.st_flags - (long) &statbuf);
    int ret = ftell(fp);
    sprintf(buf, "open file success fd=%d, fp=%p, seek_size=%d, stat_size=%lld, err=%s\n", fd, fp, ret, statbuf.st_size, strerror(errno));
    fprintf(stdout, "%s", buf);
    FILE *wfp = fopen(file, "a");
    fwrite(buf, 1, strlen(buf), wfp);
    fclose(wfp);
    fclose(fp);
  }
}

static void test_time() {
  struct mach_timebase_info info;
  int ret = mach_timebase_info(&info);
  uint64_t start = mach_absolute_time();
  printf("time ret=%d, numer=%u, denom=%u, start=%llu\n", ret, info.numer, info.denom, start);
  uint64_t end = mach_absolute_time();
  uint64_t elapsed = end - start;
  uint64_t elapsedNanoSeconds = elapsed * info.numer / info.denom;
  printf("time end=%llu, elapsed=%llu, elapsedNanoSeconds=%lluns\n", end, elapsed, elapsedNanoSeconds);
}

static void test_task_info() {
  struct task_dyld_info dyld_info;
  mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
  task_t task = mach_task_self();
  int ret = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count);
  printf("task_info task=%d, ret=%d, all_image_info_addr=%p, all_image_info_size=%llu, all_image_info_format=%d\n", task, ret, (void*)dyld_info.all_image_info_addr, dyld_info.all_image_info_size, dyld_info.all_image_info_format);
  printf("task_info size=%ld, all_image_info_addr=%ld, all_image_info_size=%ld, all_image_info_format=%ld\n", sizeof(dyld_info), (long) &dyld_info.all_image_info_addr - (long) &dyld_info, (long) &dyld_info.all_image_info_size - (long) &dyld_info, (long) &dyld_info.all_image_info_format - (long) &dyld_info);

  struct dyld_all_image_infos* infos = (struct dyld_all_image_infos*)(uintptr_t)dyld_info.all_image_info_addr;
  printf("infos=%p, size=%lu, version=%d, libSystemInitialized=%d, jitInfo=%p, dyldVersion=%s, errorMessage=%s, dyldAllImageInfosAddress=%p, uuidArrayCount=%lu, uuidArray=%p, initialImageCount=%ld, libSystemInitialized=0x%lx\n", infos, sizeof(struct dyld_all_image_infos), infos->version, infos->libSystemInitialized, infos->jitInfo, infos->dyldVersion, infos->errorMessage, infos->dyldAllImageInfosAddress, infos->uuidArrayCount, infos->uuidArray, infos->initialImageCount, (long) &infos->libSystemInitialized - (long) infos);
  for(int i=0; i < infos->infoArrayCount; ++i) {
    fprintf(stderr, "[%02d][0x%08lx] %s\n", i, (long) infos->infoArray[i].imageLoadAddress, infos->infoArray[i].imageFilePath);
  }
}

static void test_NSGetExecutablePath() {
  char buf[64];
  uint32_t size = 64;
  int ret = _NSGetExecutablePath(buf, &size);
  printf("ExecutablePath: %s, ret=%d\n", buf, ret);
}

static void test_sysctl_HW_MEMSIZE() {
  int mib[2];
  unsigned long long mem_size = 0;
  size_t size = sizeof(mem_size);

  mib[0] = CTL_HW;
  mib[1] = HW_MEMSIZE;
  int ret = sysctl(mib, 2, &mem_size, &size, NULL, 0);
  printf("test_sysctl_HW_MEMSIZE ret=%d, mem_size=%llu\n", ret, mem_size);
}

void do_test() {
  test_printf();
  test_sysctl_CTL_UNSPEC();
  test_sysctl_CTL_NET();
  test_sysctl_KERN_USRSTACK();
  test_sysctl_KERN_PROC();
  test_sysctl_KERN_VERSION();
  test_sysctl_KERN_BOOTTIME();
  test_sysctl_HW_MACHINE();
  test_sysctl_HW_MODEL();
  test_sysctl_HW_MEMSIZE();
  test_proc_pidinfo();
  test_pthread();
  test_file();
  test_time();
  test_task_info();
  test_NSGetExecutablePath();
}
