package cn.banny.emulator.linux.android.dvm;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.Module;
import com.sun.jna.Pointer;

import java.io.File;
import java.io.IOException;

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

    DvmClass resolveClass(String className);
    DvmClass findClass(String className);

    <T extends DvmObject> T getObject(long hash);

    void setJni(Jni jni);

    void printMemoryInfo();

    void deleteLocalRefs();

    DalvikModule loadLibrary(String libname, boolean forceCallInit) throws IOException;
    DalvikModule loadLibrary(File elfFile, boolean forceCallInit) throws IOException;

    int addLocalObject(DvmObject object);

    void callJNI_OnLoad(Emulator emulator, Module module) throws IOException;

    /**
     * 设置apkFile以后，可调用该值获取apk对应的packageName
     */
    String getPackageName();
}
