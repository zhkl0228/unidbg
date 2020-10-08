#include <array>
#include <cstdint>
#include <cstdio>
#include <exception>

#include <dynarmic/A32/a32.h>
#include <dynarmic/A32/config.h>

#include <dynarmic/A64/a64.h>
#include <dynarmic/A64/config.h>

#include "dynarmic.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    nativeInitialize
 * Signature: (Z)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_nativeInitialize
  (JNIEnv *env, jclass clazz, jboolean is64Bit) {
  t_dynarmic dynarmic = (t_dynarmic) calloc(1, sizeof(struct dynarmic));
  dynarmic->is64Bit = is64Bit == JNI_TRUE;
  dynarmic->memory = kh_init(memory);
  return (jlong) dynarmic;
}

/*
 * Class:     com_github_unidbg_arm_backend_dynarmic_Dynarmic
 * Method:    nativeDestroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_dynarmic_Dynarmic_nativeDestroy
  (JNIEnv *env, jclass clazz, jlong handle) {
  t_dynarmic dynarmic = (t_dynarmic) handle;
  for (khiter_t k = kh_begin(dynarmic->memory); k < kh_end(dynarmic->memory); k++) {
    if(kh_exist(dynarmic->memory, k)) {
      t_memory_page page = kh_value(dynarmic->memory, k);
      free(page);
    }
  }
  kh_destroy(memory, dynarmic->memory);
  free(dynarmic);
}

#ifdef __cplusplus
}
#endif
