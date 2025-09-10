#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

static int GetDarwinSysCtlByNameValue(const char* name) {
  {
    int mib[2];
    int values[CTL_MAXNAME+2];
    values[0] = 0;
    values[1] = 0;
    size_t size = sizeof(values);
    mib[0] = CTL_UNSPEC;
    mib[1] = 3;
    int r = sysctl(mib, 2, values, &size, (char *) name, strlen(name));
    printf("sysctl name=%s, v0=%d, v1=%d, size=%lu, ret=%d\n", name, values[0], values[1], size, r);
    if(r == 0) {
      char *mem = malloc(size);
      r = sysctl(values, 6, mem, NULL, NULL, 0);
      printf("sysctl name=%s, str=%s, ret=%d\n", name, mem, r);
      free(mem);
    }
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

int main() {
  testAarch64Info();
  return 0;
}