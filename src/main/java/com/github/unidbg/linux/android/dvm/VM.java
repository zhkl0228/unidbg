package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;

@SuppressWarnings("unused")
public interface VM {

    int JNI_FALSE = 0;
    int JNI_TRUE = 1;
    int JNI_OK = 0;
    int JNI_ERR = -1;
    int JNI_NULL = 0;
    int JNI_COMMIT = 1;
    int JNI_ABORT = 2;

    int JNIInvalidRefType = 0; // 无效引用
    int JNILocalRefType = 1; // 本地引用
    int JNIGlobalRefType = 2;  //全局引用

    Pointer getJavaVM();

    Pointer getJNIEnv();

    DvmClass resolveClass(String className, DvmClass... interfaceClasses);

    DvmClass findClass(String className);

    <T extends DvmObject<?>> T getObject(long hash);

    void setJni(Jni jni);

    void printMemoryInfo();

    void deleteLocalRefs();

    DalvikModule loadLibrary(String libname, boolean forceCallInit) throws IOException;
    DalvikModule loadLibrary(File elfFile, boolean forceCallInit) throws IOException;

    int addLocalObject(DvmObject<?> object);

    void callJNI_OnLoad(Emulator<?> emulator, Module module);

    /**
     * 设置apkFile以后，可调用该值获取apk对应的packageName
     */
    String getPackageName();

    /**
     * 设置apkFile以后，可调用该方法获取资源文件
     * @return 可返回null
     */
    byte[] openAsset(String fileName);

    /**
     * 设置apkFile以后，可调用该方法获取AndroidManifest.xml
     * @return 可返回null
     */
    String getManifestXml();

    /**
     * Add not found class
     * @param className eg: sun/security/pkcs/PKCS7
     */
    void addNotFoundClass(String className);

    /**
     * VM throw exception
     */
    void throwException(DvmObject<?> throwable);

    void setVerbose(boolean verbose);
}
