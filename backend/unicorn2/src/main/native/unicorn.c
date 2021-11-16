#include "unicorn.h"

static JavaVM* cachedJVM;

static jmethodID onBlock = 0;
static jmethodID onCode = 0;
static jmethodID onBreak = 0;
static jmethodID onRead = 0;
static jmethodID onWrite = 0;
static jmethodID onInterrupt = 0;
static jmethodID onMemEvent = 0;

static void throwException(JNIEnv *env, uc_err err) {
   jclass clazz = (*env)->FindClass(env, "unicorn/UnicornException");
   if (err != UC_ERR_OK) {
      const char *msg = uc_strerror(err);
      (*env)->ThrowNew(env, clazz, msg);
   }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    nativeInitialize
 * Signature: (II)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_nativeInitialize
  (JNIEnv *env, jclass cls, jint arch, jint mode) {
  uc_engine *eng = NULL;
  uc_err err = uc_open((uc_arch)arch, (uc_mode)mode, &eng);
  if (err != UC_ERR_OK) {
    throwException(env, err);
    return 0;
  } else {
    t_unicorn unicorn = malloc(sizeof(struct unicorn));
    unicorn->bps_map = kh_init(64);
    unicorn->uc = eng;
    return (jlong) unicorn;
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    mem_map
 * Signature: (JJJI)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1map
  (JNIEnv *env, jclass cls, jlong handle, jlong address, jlong size, jint perms) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

  uc_err err = uc_mem_map(eng, (uint64_t)address, (size_t)size, (uint32_t)perms);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    reg_read
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_reg_1read__JI
  (JNIEnv *env, jclass cls, jlong handle, jint regid) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

  jlong longVal;
  uc_err err = uc_reg_read(eng, regid, &longVal);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
  return longVal;
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    reg_write
 * Signature: (JIJ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_reg_1write__JIJ
  (JNIEnv *env, jclass cls, jlong handle, jint regid, jlong value) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

  uc_err err = uc_reg_write(eng, regid, &value);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
}

static void cb_hookintr_new(uc_engine *eng, uint32_t intno, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   (*env)->CallVoidMethod(env, user_data, onInterrupt, (int)intno);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

static bool cb_eventmem_new(uc_engine *eng, uc_mem_type type,
                        uint64_t address, int size, int64_t value, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   jboolean res = (*env)->CallBooleanMethod(env, user_data, onMemEvent, (int)type, (jlong)address, (int)size, (jlong)value);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
   return res;
}

static void cb_hookcode_new(uc_engine *eng, uint64_t address, uint32_t size, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   (*env)->CallVoidMethod(env, user_data, onCode, (jlong)address, (int)size);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

static void cb_hookblock_new(uc_engine *eng, uint64_t address, uint32_t size, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   (*env)->CallVoidMethod(env, user_data, onBlock, (jlong)address, (int)size);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

static void cb_hookmem_new(uc_engine *eng, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   switch (type) {
      case UC_MEM_READ:
         (*env)->CallVoidMethod(env, user_data, onRead, (jlong)address, (int)size);
         break;
      case UC_MEM_WRITE:
         (*env)->CallVoidMethod(env, user_data, onWrite, (jlong)address, (int)size, (jlong)value);
         break;
      default:
         break;
   }
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    registerHook
 * Signature: (JIJJLcom/github/unidbg/arm/backend/unicorn/Unicorn/NewHook;)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JIJJLcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2
  (JNIEnv *env, jclass cls, jlong handle, jint type, jlong arg1, jlong arg2, jobject hook) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

    uc_hook hh = 0;
    uc_err err = UC_ERR_OK;
    uint64_t begin = (uint64_t) arg1;
    uint64_t end = (uint64_t) arg2;

    jobject data = (*env)->NewGlobalRef(env, hook);
    switch (type) {
       case UC_HOOK_CODE:           // Hook a range of code
          err = uc_hook_add((uc_engine*)eng, &hh, (uc_hook_type)type, cb_hookcode_new, data, begin, end);
          break;
       case UC_HOOK_BLOCK:          // Hook basic blocks
          err = uc_hook_add((uc_engine*)eng, &hh, (uc_hook_type)type, cb_hookblock_new, data, begin, end);
          break;
       case UC_HOOK_MEM_READ:       // Hook all memory read events.
          err = uc_hook_add((uc_engine*)eng, &hh, (uc_hook_type)type, cb_hookmem_new, data, begin, end);
          break;
       case UC_HOOK_MEM_WRITE:      // Hook all memory write events.
          err = uc_hook_add((uc_engine*)eng, &hh, (uc_hook_type)type, cb_hookmem_new, data, begin, end);
          break;
    }
    if (err != UC_ERR_OK) {
      (*env)->DeleteGlobalRef(env, data);
      throwException(env, err);
      return 0;
    }

    struct new_hook *nh = malloc(sizeof(struct new_hook));
    nh->hh = hh;
    nh->hook = data;
    return (jlong)nh;
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    registerHook
 * Signature: (JILcom/github/unidbg/arm/backend/unicorn/Unicorn/NewHook;)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JILcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2
  (JNIEnv *env, jclass cls, jlong handle, jint type, jobject hook) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

  uc_hook hh = 0;
  uc_err err = UC_ERR_OK;

  jobject data = (*env)->NewGlobalRef(env, hook);
  switch (type) {
    case UC_HOOK_INTR:           // Hook all interrupt events
      err = uc_hook_add((uc_engine*)eng, &hh, (uc_hook_type)type, cb_hookintr_new, data, 1, 0);
      break;
    case UC_HOOK_MEM_FETCH_UNMAPPED:    // Hook for all invalid memory access events
    case UC_HOOK_MEM_READ_UNMAPPED:    // Hook for all invalid memory access events
    case UC_HOOK_MEM_WRITE_UNMAPPED:    // Hook for all invalid memory access events
    case UC_HOOK_MEM_FETCH_PROT:    // Hook for all invalid memory access events
    case UC_HOOK_MEM_READ_PROT:    // Hook for all invalid memory access events
    case UC_HOOK_MEM_WRITE_PROT:    // Hook for all invalid memory access events
      err = uc_hook_add((uc_engine*)eng, &hh, (uc_hook_type)type, cb_eventmem_new, data, 1, 0);
      break;
  }
  if (err != UC_ERR_OK) {
    (*env)->DeleteGlobalRef(env, data);
    throwException(env, err);
    return 0;
  }

  struct new_hook *nh = malloc(sizeof(struct new_hook));
  nh->hh = hh;
  nh->hook = data;
  return (jlong)nh;
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    mem_write
 * Signature: (JJ[B)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1write
  (JNIEnv *env, jclass cls, jlong handle, jlong address, jbyteArray bytes) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

   jbyte *array = (*env)->GetByteArrayElements(env, bytes, NULL);
   jsize size = (*env)->GetArrayLength(env, bytes);
   uc_err err = uc_mem_write(eng, (uint64_t)address, array, (size_t)size);

   if (err != UC_ERR_OK) {
      throwException(env, err);
   }

   (*env)->ReleaseByteArrayElements(env, bytes, array, JNI_ABORT);
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    mem_read
 * Signature: (JJJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1read
  (JNIEnv *env, jclass cls, jlong handle, jlong address, jlong size) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

   jbyteArray bytes = (*env)->NewByteArray(env, (jsize)size);
   jbyte *array = (*env)->GetByteArrayElements(env, bytes, NULL);
   uc_err err = uc_mem_read(eng, (uint64_t)address, array, (size_t)size);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
   (*env)->ReleaseByteArrayElements(env, bytes, array, 0);
   return bytes;
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    emu_start
 * Signature: (JJJJJ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_emu_1start
  (JNIEnv *env, jclass cls, jlong handle, jlong begin, jlong until, jlong timeout, jlong count) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

   uc_err err = uc_emu_start(eng, (uint64_t)begin, (uint64_t)until, (uint64_t)timeout, (size_t)count);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    emu_stop
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_emu_1stop
  (JNIEnv *env, jclass cls, jlong handle) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

   uc_err err = uc_emu_stop(eng);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    mem_unmap
 * Signature: (JJJ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1unmap
  (JNIEnv *env, jclass cls, jlong handle, jlong address, jlong size) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

   uc_err err = uc_mem_unmap(eng, (uint64_t)address, (size_t)size);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    mem_protect
 * Signature: (JJJI)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1protect
  (JNIEnv *env, jclass cls, jlong handle, jlong address, jlong size, jint perms) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

   uc_err err = uc_mem_protect(eng, (uint64_t)address, (size_t)size, (uint32_t)perms);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

static JNINativeMethod s_methods[] = {
        {"registerHook",           "(JIJJLcom/github/unidbg/arm/backend/unicorn/Unicorn$NewHook;)J",          (void *) Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JIJJLcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2 },
        {"registerHook",           "(JILcom/github/unidbg/arm/backend/unicorn/Unicorn$NewHook;)J",            (void *) Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JILcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2 }
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) {
    JNIEnv *env;
    if (JNI_OK != (*jvm)->GetEnv(jvm, (void **)&env, JNI_VERSION_1_6)) {
       return JNI_ERR;
    }
    jclass clz = (*env)->FindClass(env, "com/github/unidbg/arm/backend/unicorn/Unicorn");
    if ((*env)->ExceptionCheck(env)) {
       return JNI_ERR;
    }
    jclass newHookClass = (*env)->FindClass(env, "com/github/unidbg/arm/backend/unicorn/Unicorn$NewHook");
    if ((*env)->ExceptionCheck(env)) {
       return JNI_ERR;
    }

    onBlock = (*env)->GetMethodID(env, newHookClass, "onBlock", "(JI)V");
    onCode = (*env)->GetMethodID(env, newHookClass, "onCode", "(JI)V");
    onBreak = (*env)->GetMethodID(env, newHookClass, "onBreak", "(JI)V");
    onRead = (*env)->GetMethodID(env, newHookClass, "onRead", "(JI)V");
    onWrite = (*env)->GetMethodID(env, newHookClass, "onWrite", "(JIJ)V");
    onInterrupt = (*env)->GetMethodID(env, newHookClass, "onInterrupt", "(I)V");
    onMemEvent = (*env)->GetMethodID(env, newHookClass, "onMemEvent", "(IJIJ)Z");

    int len = sizeof(s_methods) / sizeof(s_methods[0]);
    if ((*env)->RegisterNatives(env, clz, s_methods, len)) {
        return JNI_ERR;
    }

    cachedJVM = jvm;

    return JNI_VERSION_1_6;
}
