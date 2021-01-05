#include "com_github_unidbg_arm_backend_hypervisor_Hypervisor.h"

#include <assert.h>

#include <Hypervisor/Hypervisor.h>

// Diagnostics
#define HYP_ASSERT_SUCCESS(ret) assert((hv_return_t) (ret) == HV_SUCCESS)

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    setHypervisorCallback
 * Signature: (JLcom/github/unidbg/arm/backend/hypervisor/HypervisorCallback;)I
 */
JNIEXPORT jint JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_setHypervisorCallback
  (JNIEnv *env, jclass clazz, jlong handle, jobject callback) {
  return 0;
}

/*
 * Class:     com_github_unidbg_arm_backend_hypervisor_Hypervisor
 * Method:    createVM
 * Signature: (Z)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_hypervisor_Hypervisor_createVM
  (JNIEnv *env, jclass clazz, jboolean is64Bit) {
  // Create the VM
  HYP_ASSERT_SUCCESS(hv_vm_create(NULL));
  return 0;
}
