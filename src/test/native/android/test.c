#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

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

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  fprintf(stderr, "Start test, stdin=%p, stdout=%p, stderr=%p, size=%lu\n", stdin, stdout, stderr, (unsigned long) sizeof(*stdout));
  test_stat();
  test_dirent();
  test_ioctl();
  printf("Press any key to exit\n");
  getchar();
  return 0;
}
