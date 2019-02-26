package cn.banny.emulator.linux.android.dvm;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.linux.android.dvm.api.*;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.util.Collections;
import java.util.Locale;

class DvmMethod implements Hashable {

    private static final Log log = LogFactory.getLog(DvmMethod.class);

    private final DvmClass dvmClass;
    private final String methodName;
    private final String args;

    DvmMethod(DvmClass dvmClass, String methodName, String args) {
        this.dvmClass = dvmClass;
        this.methodName = methodName;
        this.args = args;
    }

    DvmObject callStaticObjectMethod(Emulator emulator) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallStaticObjectMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticObjectMethod(vm, dvmClass, signature, methodName, args, emulator);
    }

    DvmObject callStaticObjectMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallStaticObjectMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        switch (signature) {
            case "com/android/internal/os/BinderInternal->getContextObject()Landroid/os/IBinder;":
                return new Binder(dvmClass.vm.resolveClass("android/os/IBinder"), signature);
            case "android/app/ActivityThread->currentActivityThread()Landroid/app/ActivityThread;":
                return new DvmObject<>(dvmClass, methodName);
            case "android/app/ActivityThread->currentApplication()Landroid/app/Application;":
                return new DvmObject<>(vm.resolveClass("android/app/Application"), signature);
            case "java/util/Locale->getDefault()Ljava/util/Locale;":
                return new DvmObject<>(dvmClass, Locale.getDefault());
            case "android/os/ServiceManagerNative->asInterface(Landroid/os/IBinder;)Landroid/os/IServiceManager;":
                return new ServiceManager(vm.resolveClass("android/os/IServiceManager"), signature);
            case "com/android/internal/telephony/ITelephony$Stub->asInterface(Landroid/os/IBinder;)Lcom/android/internal/telephony/ITelephony;":
                return vaList.getObject(0);
        }
        return vm.jni.callStaticObjectMethodV(vm, dvmClass, signature, methodName, args, vaList);
    }

    DvmObject callObjectMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallObjectMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        switch (signature) {
            case "android/app/Application->getAssets()Landroid/content/res/AssetManager;":
                return new AssetManager(vm.resolveClass("android/content/res/AssetManager"), signature);
            case "android/app/Application->getClassLoader()Ljava/lang/ClassLoader;":
                return new cn.banny.emulator.linux.android.dvm.api.ClassLoader(vm.resolveClass("dalvik/system/PathClassLoader"), signature);
            case "android/app/Application->getContentResolver()Landroid/content/ContentResolver;":
                return new DvmObject<>(vm.resolveClass("android/content/ContentResolver"), signature);
            case "java/util/ArrayList->get(I)Ljava/lang/Object;":
                int index = vaList.getInt(0);
                ArrayListObject arrayList = (ArrayListObject) dvmObject;
                return arrayList.getValue().get(index);
            case "android/app/Application->getSystemService(Ljava/lang/String;)Ljava/lang/Object;":
                StringObject serviceName = vaList.getObject(0);
                return new SystemService(vm, serviceName.getValue());
            case "java/lang/String->toString()Ljava/lang/String;":
                return dvmObject;
            case "java/lang/Class->getName()Ljava/lang/String;":
                return new StringObject(vm, ((DvmClass) dvmObject).getClassName());
            case "android/view/accessibility/AccessibilityManager->getEnabledAccessibilityServiceList(I)Ljava/util/List;":
                return new ArrayListObject(vm, Collections.<DvmObject>emptyList());
            case "java/util/Enumeration->nextElement()Ljava/lang/Object;":
                return ((Enumeration) dvmObject).nextElement();
            case "java/util/Locale->getLanguage()Ljava/lang/String;":
                Locale locale = (Locale) dvmObject.getValue();
                return new StringObject(vm, locale.getLanguage());
            case "java/util/Locale->getCountry()Ljava/lang/String;":
                locale = (Locale) dvmObject.getValue();
                return new StringObject(vm, locale.getCountry());
            case "android/os/IServiceManager->getService(Ljava/lang/String;)Landroid/os/IBinder;":
                ServiceManager serviceManager = (ServiceManager) dvmObject;
                return serviceManager.getService(vm, vaList.<StringObject>getObject(0).getValue());
            case "java/io/File->getAbsolutePath()Ljava/lang/String;":
                File file = (File) dvmObject.getValue();
                return new StringObject(vm, file.getAbsolutePath());
        }
        return vm.jni.callObjectMethodV(vm, dvmObject, signature, methodName, args, vaList);
    }

    int callIntMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callIntMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        switch (signature) {
            case "android/os/Bundle->getInt(Ljava/lang/String;)I":
                Bundle bundle = (Bundle) dvmObject;
                return bundle.getInt(vaList.<StringObject>getObject(0).getValue());
            case "java/util/ArrayList->size()I":
                ArrayListObject list = (ArrayListObject) dvmObject;
                return list.size();
        }
        return vm.jni.callIntMethodV(vm, dvmObject, signature, methodName, args, vaList);
    }

    int callBooleanMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callBooleanMethodV signature=" + signature);
        }
        switch (signature) {
            case "java/util/Enumeration->hasMoreElements()Z":
                return ((Enumeration) dvmObject).hasMoreElements() ? VM.JNI_TRUE : VM.JNI_FALSE;
        }
        return dvmClass.vm.jni.callBooleanMethodV(dvmClass.vm, dvmObject, signature, methodName, args, vaList) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callStaticIntMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticIntMethodV signature=" + signature);
        }
        return dvmClass.vm.jni.callStaticIntMethodV(signature, vaList);
    }

    long callStaticLongMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticLongMethodV signature=" + signature);
        }
        return dvmClass.vm.jni.callStaticLongMethodV(signature, vaList);
    }

    int callStaticBooleanMethodV() {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticBooleanMethodV signature=" + signature);
        }
        return dvmClass.vm.jni.callStaticBooleanMethodV(signature) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    void callStaticVoidMethodV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticVoidMethodV signature=" + signature);
        }
        dvmClass.vm.jni.callStaticVoidMethodV(signature, vaList);
    }

    int newObjectV(VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("newObjectV signature=" + signature);
        }
        return dvmClass.vm.addObject(dvmClass.vm.jni.newObjectV(dvmClass, signature, vaList), false);
    }

    int newObject(Emulator emulator) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("newObject signature=" + signature);
        }
        return dvmClass.vm.addObject(dvmClass.vm.jni.newObject(dvmClass, signature, emulator), false);
    }
}
