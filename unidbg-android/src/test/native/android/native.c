#include <stdio.h>
#include "com_github_unidbg_android_JniTest.h"
/*
 * Class:     com_github_unidbg_android_JniTest
 * Method:    testJni
 * Signature: (Ljava/lang/String;JIDZSFDBJF)V
 */
JNIEXPORT void JNICALL Java_com_github_unidbg_android_JniTest_testJni
  (JNIEnv *env, jclass clazz, jstring str, jlong l1, jint i, jdouble d1, jboolean b, jshort s, jfloat f1, jdouble d2, jbyte bs, jlong l2, jfloat f2) {
  const char *bytes = (*env)->GetStringUTFChars(env, str, NULL);
  printf("testJni str=%s, l1=0x%llx, i=0x%x, d1=%f, b=%d, s=0x%x, f1=%f, d2=%f, bs=0x%x, l2=0x%llx, f2=%f\n", bytes, l1, i, d1, b, s, f1, d2, bs, l2, f2);
  (*env)->ReleaseStringUTFChars(env, str, bytes);
}

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
