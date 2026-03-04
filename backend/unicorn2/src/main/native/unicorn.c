#include "unicorn.h"

void armeb_uc_init() {
  fprintf(stderr, "Unsupported armeb\n");
  abort();
}

void arm64eb_uc_init() {
  fprintf(stderr, "Unsupported arm64eb\n");
  abort();
}

void arm64eb_context_reg_read() {
  fprintf(stderr, "Unsupported arm64eb\n");
  abort();
}

void arm64eb_context_reg_write() {
  fprintf(stderr, "Unsupported arm64eb\n");
  abort();
}

void ARM64_REGS_STORAGE_SIZE_aarch64eb() {
  fprintf(stderr, "Unsupported aarch64eb\n");
  abort();
}

static JavaVM* cachedJVM;

static jmethodID onBlock = 0;
static jmethodID onCode = 0;
static jmethodID onBreak = 0;
static jmethodID onRead = 0;
static jmethodID onWrite = 0;
static jmethodID onInterrupt = 0;
static jmethodID onMemEvent = 0;

static void throwException(JNIEnv *env, uc_err err) {
  if (err != UC_ERR_OK) {
    const char *msg = uc_strerror(err);
    jclass clazz = (*env)->FindClass(env, "unicorn/UnicornException");
    (*env)->ThrowNew(env, clazz, msg);
  }
}

static JNIEnv* jni_env_attach(int *need_detach) {
  JNIEnv *env;
  if ((*cachedJVM)->GetEnv(cachedJVM, (void**)&env, JNI_VERSION_1_6) == JNI_OK) {
    *need_detach = 0;
  } else {
    (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
    *need_detach = 1;
  }
  return env;
}

static void jni_env_detach(int need_detach) {
  if (need_detach) {
    (*cachedJVM)->DetachCurrentThread(cachedJVM);
  }
}

static void track_hook(t_unicorn unicorn, struct new_hook *nh) {
  nh->next = unicorn->hook_list;
  unicorn->hook_list = nh;
}

static void untrack_hook(t_unicorn unicorn, struct new_hook *nh) {
  struct new_hook **pp = &unicorn->hook_list;
  while (*pp) {
    if (*pp == nh) {
      *pp = nh->next;
      return;
    }
    pp = &(*pp)->next;
  }
}

static void update_bps(t_unicorn unicorn) {
  int n = kh_size(unicorn->bps_map);
  if (n <= SEARCH_BPS_COUNT) {
    int idx = 0;
    khiter_t k;
    for (k = kh_begin(unicorn->bps_map); k < kh_end(unicorn->bps_map); k++) {
      if (kh_exist(unicorn->bps_map, k)) {
        uint64_t key = kh_key(unicorn->bps_map, k);
        unicorn->bps[idx++] = key;
      }
    }
  }
}

static inline bool hitBreakPoint(uint64_t bps[], int n, uint64_t address) {
  int i;
  for (i = 0; i < n; i++) {
    if (bps[i] == address) {
      return true;
    }
  }
  return false;
}

static inline bool shouldBreak(t_unicorn unicorn, uint64_t address) {
  int n = kh_size(unicorn->bps_map);
  if (n <= 0) {
    return false;
  }
  if (n > SEARCH_BPS_COUNT) {
    return kh_get(64, unicorn->bps_map, address) != kh_end(unicorn->bps_map);
  }
  return hitBreakPoint(unicorn->bps, n, address);
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
  }
  if (arch == UC_ARCH_ARM64) {
    err = uc_ctl_set_cpu_model(eng, UC_CPU_ARM64_MAX);
  } else {
    err = uc_ctl_set_cpu_model(eng, UC_CPU_ARM_CORTEX_A15);
  }
  if (err != UC_ERR_OK) {
    fprintf(stderr, "set uc_ctl_set_cpu_model failed: err=%d\n", err);
    uc_close(eng);
    throwException(env, err);
    return 0;
  }
  t_unicorn unicorn = malloc(sizeof(struct unicorn));
  memset(unicorn, 0, sizeof(struct unicorn));
  unicorn->bps_map = kh_init(64);
  unicorn->uc = eng;
  unicorn->singleStep = 0;
  unicorn->fastDebug = JNI_TRUE;
  unicorn->hook_list = NULL;
  return (jlong) unicorn;
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
  jlong longVal = 0;
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
  struct new_hook *nh = (struct new_hook *) user_data;
  int need_detach;
  JNIEnv *env = jni_env_attach(&need_detach);
  (*env)->CallVoidMethod(env, nh->hook, onInterrupt, (int)intno);
  jni_env_detach(need_detach);
}

static bool cb_eventmem_new(uc_engine *eng, uc_mem_type type,
                        uint64_t address, int size, int64_t value, void *user_data) {
  struct new_hook *nh = (struct new_hook *) user_data;
  int need_detach;
  JNIEnv *env = jni_env_attach(&need_detach);
  jboolean res = (*env)->CallBooleanMethod(env, nh->hook, onMemEvent, (int)type, (jlong)address, (int)size, (jlong)value);
  jni_env_detach(need_detach);
  return res;
}

static void cb_hookcode_new(uc_engine *eng, uint64_t address, uint32_t size, void *user_data) {
  struct new_hook *nh = (struct new_hook *) user_data;
  int need_detach;
  JNIEnv *env = jni_env_attach(&need_detach);
  (*env)->CallVoidMethod(env, nh->hook, onCode, (jlong)address, (int)size);
  jni_env_detach(need_detach);
}

static void cb_hookblock_new(uc_engine *eng, uint64_t address, uint32_t size, void *user_data) {
  struct new_hook *nh = (struct new_hook *) user_data;
  int need_detach;
  JNIEnv *env = jni_env_attach(&need_detach);
  (*env)->CallVoidMethod(env, nh->hook, onBlock, (jlong)address, (int)size);
  jni_env_detach(need_detach);
}

static void cb_hookmem_new(uc_engine *eng, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data) {
  struct new_hook *nh = (struct new_hook *) user_data;
  int need_detach;
  JNIEnv *env = jni_env_attach(&need_detach);
  switch (type) {
    case UC_MEM_READ:
      (*env)->CallVoidMethod(env, nh->hook, onRead, (jlong)address, (int)size);
      break;
    case UC_MEM_WRITE:
      (*env)->CallVoidMethod(env, nh->hook, onWrite, (jlong)address, (int)size, (jlong)value);
      break;
    default:
      break;
  }
  jni_env_detach(need_detach);
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    removeCache
 * Signature: (JJJ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_removeCache
  (JNIEnv *env, jclass cls, jlong handle, jlong arg1, jlong arg2) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;
  uint64_t begin = (uint64_t) arg1;
  uint64_t end = (uint64_t) arg2;
  uc_err err = uc_ctl_remove_cache(eng, begin, end);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
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

  struct new_hook *nh = malloc(sizeof(struct new_hook));
  nh->hook = (*env)->NewGlobalRef(env, hook);
  nh->unicorn = unicorn;
  nh->next = NULL;

  switch (type) {
    case UC_HOOK_CODE:
      err = uc_hook_add(eng, &hh, (uc_hook_type)type, cb_hookcode_new, nh, begin, end);
      break;
    case UC_HOOK_BLOCK:
      err = uc_hook_add(eng, &hh, (uc_hook_type)type, cb_hookblock_new, nh, begin, end);
      break;
    case UC_HOOK_MEM_READ:
      err = uc_hook_add(eng, &hh, (uc_hook_type)type, cb_hookmem_new, nh, begin, end);
      break;
    case UC_HOOK_MEM_WRITE:
      err = uc_hook_add(eng, &hh, (uc_hook_type)type, cb_hookmem_new, nh, begin, end);
      break;
    default:
      (*env)->DeleteGlobalRef(env, nh->hook);
      free(nh);
      throwException(env, UC_ERR_ARG);
      return 0;
  }
  if (err != UC_ERR_OK) {
    (*env)->DeleteGlobalRef(env, nh->hook);
    free(nh);
    throwException(env, err);
    return 0;
  }
  nh->hh = hh;
  track_hook(unicorn, nh);
  return (jlong)nh;
}

static void hook_count_cb(uc_engine *eng, uint64_t address, uint32_t size, void *user_data) {
  struct new_hook *nh = (struct new_hook *) user_data;
  nh->unicorn->emu_counter++;

  if (nh->unicorn->emu_counter > nh->unicorn->emu_count) {
    uc_emu_stop(eng);

    int need_detach;
    JNIEnv *env = jni_env_attach(&need_detach);
    (*env)->CallVoidMethod(env, nh->hook, onCode, (jlong)address, (int)size);
    jni_env_detach(need_detach);
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    register_emu_count_hook
 * Signature: (JJLcom/github/unidbg/arm/backend/unicorn/Unicorn/NewHook;)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_register_1emu_1count_1hook
  (JNIEnv *env, jclass cls, jlong handle, jlong emu_count, jobject hook) {
  t_unicorn unicorn = (t_unicorn) handle;
  unicorn->emu_count = emu_count;

  if (emu_count > 0 && unicorn->count_hook == 0) {
    struct new_hook *nh = malloc(sizeof(struct new_hook));
    nh->hook = (*env)->NewGlobalRef(env, hook);
    nh->unicorn = unicorn;
    nh->next = NULL;

    uc_err err = uc_hook_add(unicorn->uc, &unicorn->count_hook, UC_HOOK_CODE, hook_count_cb, nh, 1, 0);
    if (err != UC_ERR_OK) {
      (*env)->DeleteGlobalRef(env, nh->hook);
      free(nh);
      throwException(env, err);
      return 0;
    }
    nh->hh = unicorn->count_hook;
    track_hook(unicorn, nh);
    return (jlong)nh;
  }
  return 0;
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

  struct new_hook *nh = malloc(sizeof(struct new_hook));
  nh->hook = (*env)->NewGlobalRef(env, hook);
  nh->unicorn = unicorn;
  nh->next = NULL;

  switch (type) {
    case UC_HOOK_INTR:
      err = uc_hook_add(eng, &hh, (uc_hook_type)type, cb_hookintr_new, nh, 1, 0);
      break;
    case UC_HOOK_MEM_FETCH_UNMAPPED:
    case UC_HOOK_MEM_READ_UNMAPPED:
    case UC_HOOK_MEM_WRITE_UNMAPPED:
    case UC_HOOK_MEM_FETCH_PROT:
    case UC_HOOK_MEM_READ_PROT:
    case UC_HOOK_MEM_WRITE_PROT:
      err = uc_hook_add(eng, &hh, (uc_hook_type)type, cb_eventmem_new, nh, 1, 0);
      break;
    default:
      (*env)->DeleteGlobalRef(env, nh->hook);
      free(nh);
      throwException(env, UC_ERR_ARG);
      return 0;
  }
  if (err != UC_ERR_OK) {
    (*env)->DeleteGlobalRef(env, nh->hook);
    free(nh);
    throwException(env, err);
    return 0;
  }
  nh->hh = hh;
  track_hook(unicorn, nh);
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
  unicorn->emu_counter = 0;
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

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    nativeDestroy
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_nativeDestroy
  (JNIEnv *env, jclass cls, jlong handle) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

  struct new_hook *nh = unicorn->hook_list;
  while (nh) {
    struct new_hook *next = nh->next;
    (*env)->DeleteGlobalRef(env, nh->hook);
    uc_hook_del(eng, nh->hh);
    free(nh);
    nh = next;
  }

  uc_err err = uc_close(eng);
  kh_destroy(64, unicorn->bps_map);
  free(unicorn);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    hook_del
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_hook_1del
  (JNIEnv *env, jclass cls, jlong hh) {
  struct new_hook *nh = (struct new_hook *) hh;
  t_unicorn unicorn = nh->unicorn;
  uc_engine *eng = unicorn->uc;
  untrack_hook(unicorn, nh);
  (*env)->DeleteGlobalRef(env, nh->hook);
  uc_err err = uc_hook_del(eng, nh->hh);
  free(nh);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    context_alloc
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_context_1alloc
  (JNIEnv *env, jclass cls, jlong handle) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;
  uc_context *ctx;
  uc_err err = uc_context_alloc(eng, &ctx);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
  return (jlong)ctx;
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    free
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_free
  (JNIEnv *env, jclass cls, jlong ctx) {
  uc_err err = uc_free((void *)ctx);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    context_save
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_context_1save
  (JNIEnv *env, jclass cls, jlong handle, jlong ctx) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;
  uc_err err = uc_context_save(eng, (uc_context*)ctx);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    context_restore
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_context_1restore
  (JNIEnv *env, jclass cls, jlong handle, jlong ctx) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;
  uc_err err = uc_context_restore(eng, (uc_context*)ctx);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    reg_read
 * Signature: (JII)[B
 */
JNIEXPORT jbyteArray JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_reg_1read__JII
  (JNIEnv *env, jclass cls, jlong handle, jint regid, jint regsz) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;
  jbyteArray regval = (*env)->NewByteArray(env, (jsize)regsz);
  jbyte *array = (*env)->GetByteArrayElements(env, regval, NULL);
  uc_err err = uc_reg_read(eng, (int)regid, (void *)array);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
  (*env)->ReleaseByteArrayElements(env, regval, array, 0);
  return regval;
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    reg_write
 * Signature: (JI[B)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_reg_1write__JI_3B
  (JNIEnv *env, jclass cls, jlong handle, jint regid, jbyteArray value) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;
  jbyte *array = (*env)->GetByteArrayElements(env, value, NULL);
  uc_err err = uc_reg_write(eng, (int)regid, (void *)array);
  if (err != UC_ERR_OK) {
    throwException(env, err);
  }
  (*env)->ReleaseByteArrayElements(env, value, array, JNI_ABORT);
}

static void cb_debugger(uc_engine *eng, uint64_t address, uint32_t size, void *user_data) {
  struct new_hook *nh = (struct new_hook *) user_data;
  t_unicorn u = nh->unicorn;

  bool hit_single_step = u->singleStep > 0 && --u->singleStep == 0;
  bool hit_bp = shouldBreak(u, address);

  if (hit_single_step || hit_bp) {
    int need_detach;
    JNIEnv *env = jni_env_attach(&need_detach);
    (*env)->CallVoidMethod(env, nh->hook, onBreak, (jlong)address, (int)size);
    jni_env_detach(need_detach);
  } else if (u->fastDebug != JNI_TRUE) {
    int need_detach;
    JNIEnv *env = jni_env_attach(&need_detach);
    (*env)->CallVoidMethod(env, nh->hook, onCode, (jlong)address, (int)size);
    jni_env_detach(need_detach);
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    registerDebugger
 * Signature: (JJJLcom/github/unidbg/arm/backend/unicorn/Unicorn/NewHook;)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerDebugger
  (JNIEnv *env, jclass cls, jlong handle, jlong arg1, jlong arg2, jobject hook) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;

  uc_hook hh = 0;
  uint64_t begin = (uint64_t) arg1;
  uint64_t end = (uint64_t) arg2;

  struct new_hook *nh = malloc(sizeof(struct new_hook));
  nh->hook = (*env)->NewGlobalRef(env, hook);
  nh->unicorn = unicorn;
  nh->next = NULL;

  uc_err err = uc_hook_add(eng, &hh, UC_HOOK_CODE, cb_debugger, nh, begin, end);
  if (err != UC_ERR_OK) {
    (*env)->DeleteGlobalRef(env, nh->hook);
    free(nh);
    throwException(env, err);
    return 0;
  }
  nh->hh = hh;
  track_hook(unicorn, nh);
  return (jlong)nh;
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    setFastDebug
 * Signature: (JZ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_setFastDebug
  (JNIEnv *env, jclass cls, jlong handle, jboolean fastDebug) {
  t_unicorn unicorn = (t_unicorn) handle;
  unicorn->fastDebug = fastDebug;
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    setSingleStep
 * Signature: (JI)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_setSingleStep
  (JNIEnv *env, jclass cls, jlong handle, jint singleStep) {
  t_unicorn unicorn = (t_unicorn) handle;
  unicorn->singleStep = singleStep;
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    addBreakPoint
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_addBreakPoint
  (JNIEnv *env, jclass cls, jlong handle, jlong address) {
  t_unicorn unicorn = (t_unicorn) handle;
  int ret;
  khiter_t k = kh_put(64, unicorn->bps_map, address, &ret);
  kh_value(unicorn->bps_map, k) = 1;
  update_bps(unicorn);
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    removeBreakPoint
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_removeBreakPoint
  (JNIEnv *env, jclass cls, jlong handle, jlong address) {
  t_unicorn unicorn = (t_unicorn) handle;
  khiter_t k = kh_get(64, unicorn->bps_map, address);
  if (k != kh_end(unicorn->bps_map)) {
    kh_del(64, unicorn->bps_map, k);
    update_bps(unicorn);
  }
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    mem_allocated_size
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1allocated_1size
  (JNIEnv *env, jclass cls, jlong handle) {
  t_unicorn unicorn = (t_unicorn) handle;
  uc_engine *eng = unicorn->uc;
  uc_mem_region *regions = NULL;
  uint32_t count = 0;
  uc_err err = uc_mem_regions(eng, &regions, &count);
  if (err != UC_ERR_OK) {
    throwException(env, err);
    return 0;
  }
  uint64_t total = 0;
  uint32_t i;
  for (i = 0; i < count; i++) {
    total += regions[i].end - regions[i].begin + 1;
  }
  uc_free(regions);
  return (jlong) total;
}

/*
 * Class:     com_github_unidbg_arm_backend_unicorn_Unicorn
 * Method:    mem_resident_size
 * Signature: (J)J
 */
JNIEXPORT jlong JNICALL Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1resident_1size
  (JNIEnv *env, jclass cls, jlong handle) {
  return Java_com_github_unidbg_arm_backend_unicorn_Unicorn_mem_1allocated_1size(env, cls, handle);
}

static JNINativeMethod s_methods[] = {
  {"registerHook", "(JIJJLcom/github/unidbg/arm/backend/unicorn/Unicorn$NewHook;)J", (void *) Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JIJJLcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2 },
  {"registerHook", "(JILcom/github/unidbg/arm/backend/unicorn/Unicorn$NewHook;)J",   (void *) Java_com_github_unidbg_arm_backend_unicorn_Unicorn_registerHook__JILcom_github_unidbg_arm_backend_unicorn_Unicorn_NewHook_2 }
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
