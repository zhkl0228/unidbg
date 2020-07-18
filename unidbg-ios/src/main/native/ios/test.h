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
#include <sys/attr.h>
#include <sys/dir.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/param.h>
#include <sys/ucred.h>
#include <sys/mount.h>

#define RTM_IFINFO	0xe

static void hex(char *buf, void *ptr, size_t size) {
  const char *data = (const char *) ptr;
  int idx = 0;
  for(int i = 0; i < size; i++) {
    idx += sprintf(&buf[idx], "%02x", data[i] & 0xff);
  }
}

static void test_printf() {
  char buf[0x40];
  memset(buf, 0, 0x40);
  snprintf(buf, 0x40, "snprintf: %p\n", buf);
  printf("printf[%p] if_nametoindex=%d, test=%s", buf, if_nametoindex("en0"), buf);
  fprintf(stdout, "ENOTDIR=0x%x, O_WRONLY=0x%x, O_RDWR=0x%x, O_NONBLOCK=0x%x, O_APPEND=0x%x, O_CREAT=0x%x, O_DIRECTORY=0x%x\n", ENOTDIR, O_WRONLY, O_RDWR, O_NONBLOCK, O_APPEND, O_CREAT, O_DIRECTORY);
  int fd = open("", 0);
  printf("test_printf sizeof(sigaction)=%lu, sizeof(iovec)=%lu, fd=%d, errno=%d, msg=%s\n", sizeof(struct	sigaction), sizeof(struct iovec), fd, errno, strerror(errno));
}

static void test_sysctl_CTL_UNSPEC() {
  int mib[2];
  int values[14];
  size_t size = sizeof(values);

  const char *name = "kern.ostype";

  mib[0] = CTL_UNSPEC;
  mib[1] = 3;
  int ret = sysctl(mib, 2, values, &size, (char *) name, strlen(name));
  printf("test_sysctl_CTL_UNSPEC ret=%d, ctl=%d, type=%d, size=%zu\n", ret, values[0], values[1], size);
}

static void test_sysctl_CTL_NET() {
  size_t buffSize = 0;
  int					mib[6] = {CTL_NET, AF_ROUTE, 0, 0, NET_RT_IFLIST, 0 };
  int ret = sysctl(mib, 6, NULL, &buffSize, NULL, 0);
  char *buf = (char *) malloc(buffSize);
  ret = sysctl(mib, 6, buf, &buffSize, NULL, 0);

  struct if_msghdr	*ifm = (struct if_msghdr *) buf;
  char *end = buf + buffSize;

  while((char*)ifm < end) {
    if(ifm->ifm_type == RTM_IFINFO) {
      struct sockaddr_dl	*sdl = (struct sockaddr_dl *) (ifm + 1);
      char *name = (char *) malloc(sdl->sdl_nlen + 1);
      memcpy(name, sdl->sdl_data, sdl->sdl_nlen);
      name[sdl->sdl_nlen] = 0;
      char *mac = (char *) malloc(128);
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
  char *machine = (char *) malloc(size);
  sysctlbyname("hw.machine", machine, &size, NULL, 0);
  printf("test_sysctl_HW_MACHINE machine=%s\n", machine);
  free(machine);
}

static void test_sysctl_KERN_OSTYPE() {
  size_t size;
  sysctlbyname("kern.ostype", NULL, &size, NULL, 0);
  char *osType = (char *) malloc(size);
  sysctlbyname("kern.ostype", osType, &size, NULL, 0);
  printf("test_sysctl_KERN_OSTYPE machine=%s\n", osType);
  free(osType);
}

static void test_sysctl_HW_MODEL() {
  size_t size;
  sysctlbyname("hw.model", NULL, &size, NULL, 0);
  char *model = (char *) malloc(size);
  sysctlbyname("hw.model", model, &size, NULL, 0);
  printf("test_sysctl_HW_MODEL model=%s\n", model);
  free(model);
}

static void test_sysctl_KERN_VERSION() {
  size_t size;
  sysctlbyname("kern.version", NULL, &size, NULL, 0);
  char *version = (char *) malloc(size);
  sysctlbyname("kern.version", version, &size, NULL, 0);
  printf("test_sysctl_KERN_VERSION version=%s\n", version);
  free(version);
}

static void test_sysctl_KERN_BOOTTIME() {
  size_t size;
  sysctlbyname("kern.boottime", NULL, &size, NULL, 0);
  char *boot_time = (char *) malloc(size);
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

extern "C" int proc_pidinfo(int pid, int flavor, uint64_t arg,  void *buffer, int buffersize);

static void test_proc_pidinfo() {
  struct proc_bsdshortinfo bsdinfo;

  pid_t pid = getpid();
  int ret = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 1, &bsdinfo, sizeof(bsdinfo));
  printf("proc_pidinfo ret=%d, pid=%d, size=%lu, pbsi_comm=%s, pbsi_flags=0x%x, pbsi_ppid=%d\n", ret, pid, sizeof(bsdinfo), bsdinfo.pbsi_comm, bsdinfo.pbsi_flags, bsdinfo.pbsi_ppid);
}

static void *thread_run(void *arg) {
  printf("thread_run arg=%p\n", arg);
  return NULL;
}

static void test_pthread() {
  char name[64];
  sprintf(name, "thread: %p", name);
  pthread_setname_np(name);
  memset(name, 0, 64);
  pthread_t thread = pthread_self();
  pthread_getname_np(thread, name, sizeof(name));
  pthread_attr_t thread_attr;
  pthread_attr_init(&thread_attr);
  size_t stack_size = 0;
  int ret = pthread_attr_getstacksize(&thread_attr, &stack_size);
  printf("pthread[%p] name=%s, ret=%d, stack_size=%lu\n", thread, name, ret, stack_size);

  ret = pthread_create(&thread, NULL, thread_run, NULL);
  pthread_detach(thread);
  printf("pthread[%p] ret=%d\n", thread, ret);
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

#define HW_CPU_FAMILY 108

static void test_sysctl_HW_CPU_FAMILY() {
  int mib[2];
  unsigned int family = 0;
  size_t size = sizeof(family);

  mib[0] = CTL_HW;
  mib[1] = HW_CPU_FAMILY;
  int ret = sysctl(mib, 2, &family, &size, NULL, 0);
  printf("test_sysctl_HW_CPU_FAMILY ret=%d, family=%u, size=%zu\n", ret, family, size);
}

static void test_getattrlist() {
  struct attrlist attrlist;
  u_int32_t attrbuf[2];	/* Length field and access modes */
  attrlist.bitmapcount = ATTR_BIT_MAP_COUNT;
  attrlist.commonattr = ATTR_CMN_USERACCESS;
  attrlist.volattr = 0;
  attrlist.dirattr = 0;
  attrlist.fileattr = 0;
  attrlist.forkattr = 0;
  int ret = getattrlist("/", &attrlist, attrbuf, sizeof(attrbuf), 0);
  printf("test_getattrlist ret=%d, len=%d, attrbuf2=%d\n", ret, attrbuf[0], attrbuf[1]);
  printf("test_getattrlist X_OK=%d, R_OK=%d, W_OK=%d\n", X_OK, R_OK, W_OK);
}

static void test_dirent() {
  struct dirent ent;
  unsigned long base = (unsigned long) &ent;
  printf("test_dirent size=%lu, d_fileno=%lu, d_name=%lu, d_name_size=%lu\n", sizeof(struct dirent), (unsigned long) &ent.d_fileno - base, (unsigned long) &ent.d_name - base, sizeof(ent.d_name));
}

static void checkDebugger() {
  int name[4];
  name[0] = CTL_KERN;
  name[1] = KERN_PROC;
  name[2] = KERN_PROC_PID;
  name[3] = getpid();
  struct kinfo_proc info;
  size_t info_size = sizeof(info);
  int error = sysctl(name, sizeof(name)/sizeof(*name), &info, &info_size, 0, 0);
  bool ret = ((info.kp_proc.p_flag & P_TRACED) !=0);
  printf("checkDebugger error=%d, ret=%d, P_TRACED=%d\n", error, ret, P_TRACED);
}

static void test_host_statistics() {
  unsigned int count = HOST_VM_INFO_COUNT;
  struct vm_statistics stats;
  mach_port_t mhs = mach_host_self();
  int ret = host_statistics(mhs, HOST_VM_INFO, (host_info_t)&stats, &count);
  size_t size = sizeof(stats);
  char *buf = (char *) malloc(size * 3);
  memset(buf, 0, size * 3);
  hex(buf, &stats, size);
  printf("test_host_statistics ret=%d, size=%lu, hex=%s\n", ret, size, buf);
  free(buf);
}

static void test_getfsstat() {
  struct statfs *mntbuf;
  int mntsize = getfsstat(0, 0, MNT_NOWAIT);
  size_t bufsize = (mntsize + 1) * sizeof(struct statfs);
  mntbuf = (struct statfs *) malloc(bufsize);
  memset(mntbuf, 0, bufsize);
  int ret = getfsstat(mntbuf, bufsize, MNT_WAIT);
  char *buf = (char *) malloc(bufsize * 3);
  memset(buf, 0, bufsize * 3);
  hex(buf, mntbuf, bufsize);
  printf("test_getfsstat mntsize=%d, bufsize=%zu, ret=%d, hex=%s\n", mntsize, bufsize, ret, buf);
  free(buf);
  free(mntbuf);
}

static void test_lr() {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  char *buf = (char *) malloc(128);
  memset(buf, 0, 128);
  hex(buf, (void *)lr, 8);
  printf("test_lr lr=%p, hex=%s\n", (void *)lr, buf);
  free(buf);
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
  test_getattrlist();
  test_dirent();
  test_sysctl_HW_CPU_FAMILY();
  test_sysctl_KERN_OSTYPE();
  checkDebugger();
  test_host_statistics();
  test_getfsstat();
  test_lr();
}

__attribute__((constructor))
void init() {
  uintptr_t lr = 1;
  __asm__(
    "mov %[LR], lr\n"
    :[LR]"=r"(lr)
  );
  lr &= (~(0x4000-1));
  char *buf = (char *) malloc(128);
  memset(buf, 0, 128);
  hex(buf, (void *)lr, 8);
  printf("constructor lr=%p, hex=%s\n", (void *)lr, buf);
  free(buf);
}
