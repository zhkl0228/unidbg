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
  const char *ap = (*env)->GetStringUTFChars(env, str, NULL);
  const char *bp = (*env)->GetStringUTFChars(env, str, NULL);
  printf("testJni bytes=%p, ap=%p, bp=%p\n", bytes, ap, bp);
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
  jmethodID testStaticFloat = (*env)->GetStaticMethodID(env, cAndroidTest, "testStaticFloat", "(FD)F");
  jmethodID testStaticDouble = (*env)->GetStaticMethodID(env, cAndroidTest, "testStaticDouble", "(FD)D");
  jfieldID testStaticBoolean = (*env)->GetStaticFieldID(env, cAndroidTest, "staticBooleanField", "Z");
  jfieldID testStaticDoubleField = (*env)->GetStaticFieldID(env, cAndroidTest, "staticDoubleField", "D");
  jfieldID testStaticFloatField = (*env)->GetStaticFieldID(env, cAndroidTest, "staticFloatField", "F");

  jfloat floatValue = (*env)->CallStaticFloatMethod(env, cAndroidTest, testStaticFloat, 0.00123456789012345F, 0.00456789123456);
  (*env)->SetStaticFloatField(env, cAndroidTest, testStaticFloatField, floatValue + 1.0);
  jdouble doubleValue = (*env)->CallStaticDoubleMethod(env, cAndroidTest, testStaticDouble, 0.00123456789012345F, 0.00456789123456);
  (*env)->SetStaticDoubleField(env, cAndroidTest, testStaticDoubleField, doubleValue + 2.0);
  jboolean booleanValue = (*env)->GetStaticBooleanField(env, cAndroidTest, testStaticBoolean);

  jmethodID constructor = (*env)->GetMethodID(env, cAndroidTest, "<init>", "()V");
  jobject inst = (*env)->NewObject(env, cAndroidTest, constructor);
  jfieldID testDouble = (*env)->GetFieldID(env, cAndroidTest, "doubleField", "D");
  jfieldID testFloat = (*env)->GetFieldID(env, cAndroidTest, "floatField", "F");
  (*env)->SetFloatField(env, inst, testFloat, floatValue + 3.0);
  (*env)->SetDoubleField(env, inst, testDouble, doubleValue + 4.0);

  char buf[10240];
  snprintf(buf, 10240, "%fF", floatValue);
  printf("JNI_OnLoad floatValue=%s, doubleValue=%fD, booleanValue=%d, sizeof(jfloat)=%zu, sizeof(jdouble)=%zu\n", buf, doubleValue, booleanValue, sizeof(jfloat), sizeof(jdouble));

  return JNI_VERSION_1_6;
}
