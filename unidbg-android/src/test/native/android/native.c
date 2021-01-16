#include <stdio.h>
#include <jni.h>

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  JNIEnv *env;
  if (JNI_OK != (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6)) {
    return JNI_ERR;
  }
  jclass cAndroidTest = (*env)->FindClass(env, "com/github/unidbg/android/AndroidTest");
  if ((*env)->ExceptionCheck(env)) {
    return JNI_ERR;
  }
  jmethodID testStaticFloat = (*env)->GetStaticMethodID(env, cAndroidTest, "testStaticFloat", "()F");
  jfieldID testBoolean = (*env)->GetStaticFieldID(env, cAndroidTest, "staticBooleanField", "Z");

  jfloat floatValue = (*env)->CallStaticFloatMethod(env, cAndroidTest, testStaticFloat);
  jboolean booleanValue = (*env)->GetStaticBooleanField(env, cAndroidTest, testBoolean);

  char buf[10240];
  snprintf(buf, 10240, "%ff", floatValue);
  printf("JNI_OnLoad floatValue=%s, booleanValue=%d, sizeof(jfloat)=%zu\n", buf, booleanValue, sizeof(jfloat));

  return JNI_VERSION_1_6;
}
