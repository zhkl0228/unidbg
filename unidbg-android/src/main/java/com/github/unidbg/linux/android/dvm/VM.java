package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.linux.android.dvm.apk.AssetResolver;
import com.github.unidbg.spi.LibraryFile;
import com.sun.jna.Pointer;
import net.dongliu.apk.parser.bean.CertificateMeta;

import java.io.File;

@SuppressWarnings("unused")
public interface VM {

    int JNI_FALSE = 0;
    int JNI_TRUE = 1;
    int JNI_OK = 0;
    int JNI_ERR = -1; /* unknown error */
    int JNI_NULL = 0;
    int JNI_COMMIT = 1;
    int JNI_ABORT = 2;

    int JNI_VERSION_1_1 = 0x00010001;
    int JNI_VERSION_1_2 = 0x00010002;
    int JNI_VERSION_1_4 = 0x00010004;
    int JNI_VERSION_1_6 = 0x00010006;
    int JNI_VERSION_1_8 = 0x00010008;

    int JNIInvalidRefType = 0; // 无效引用
    int JNILocalRefType = 1; // 本地引用
    int JNIGlobalRefType = 2;  //全局引用
    int JNIWeakGlobalRefType = 3;

    Pointer getJavaVM();

    Pointer getJNIEnv();

    /**
     * @param interfaceClasses 如果不为空的话，第一个为superClass，其它的为interfaces
     */
    DvmClass resolveClass(String className, DvmClass... interfaceClasses);

    DvmClass findClass(String className);

    <T extends DvmObject<?>> T getObject(int hash);

    /**
     * Use vm.setDvmClassFactory(new ProxyClassFactory()) instead
     */
    void setJni(Jni jni);

    void printMemoryInfo();

    DalvikModule loadLibrary(String libname, boolean forceCallInit);
    DalvikModule loadLibrary(String libname, byte[] raw, boolean forceCallInit);
    DalvikModule loadLibrary(File elfFile, boolean forceCallInit);

    LibraryFile findLibrary(String soName);

    int addLocalObject(DvmObject<?> object);
    int addGlobalObject(DvmObject<?> object);

    void callJNI_OnLoad(Emulator<?> emulator, Module module);

    /**
     * 设置apkFile以后，可调用该值获取apk对应的packageName
     */
    String getPackageName();
    String getVersionName();
    long getVersionCode();

    /**
     * 设置apkFile以后，可调用该方法获取资源文件
     * @return 可返回null
     */
    byte[] openAsset(String fileName);

    /**
     * 设置apkFile以后，可调用该方法获取压缩包内容
     * @return 可返回null
     */
    byte[] unzip(String path);

    void setAssetResolver(AssetResolver assetResolver);

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

    void setDvmClassFactory(DvmClassFactory factory);

    Emulator<?> getEmulator();

    CertificateMeta[] getSignatures();

}
