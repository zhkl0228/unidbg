package cn.banny.emulator.linux.android.dvm;

import cn.banny.emulator.linux.android.dvm.api.*;
import cn.banny.emulator.linux.android.dvm.wrapper.DvmInteger;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.UnsupportedEncodingException;
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

    DvmObject callStaticObjectMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("CallStaticObjectMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        return vm.jni.callStaticObjectMethod(vm, dvmClass, signature, methodName, args, varArg);
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

    DvmObject callObjectMethod(DvmObject dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callObjectMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        switch (signature) {
            case "java/lang/String->getBytes(Ljava/lang/String;)[B": {
                StringObject string = (StringObject) dvmObject;
                StringObject encoding = varArg.getObject(0);
                System.err.println("string=" + string.getValue() + ", encoding=" + encoding.getValue());
                try {
                    return new ByteArray(string.getValue().getBytes(encoding.value));
                } catch (UnsupportedEncodingException e) {
                    throw new IllegalStateException(e);
                }
            }
            case "android/content/Context->getPackageManager()Landroid/content/pm/PackageManager;":
                return new DvmObject<Object>(vm.resolveClass("android/content/pm/PackageManager"), null);
            case "android/content/Context->getPackageName()Ljava/lang/String;": {
                String packageName = vm.getPackageName();
                if (packageName != null) {
                    return new StringObject(vm, packageName);
                }
            }
            case "android/content/pm/PackageManager->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;": {
                StringObject packageName = varArg.getObject(0);
                int flags = varArg.getInt(1);
                if (log.isDebugEnabled()) {
                    log.debug("getPackageInfo packageName=" + packageName.getValue() + ", flags=0x" + Integer.toHexString(flags));
                }
                return new PackageInfo(vm, packageName.value, flags);
            }
            case "android/content/pm/Signature->toByteArray()[B": {
                if (dvmObject instanceof Signature) {
                    Signature sig = (Signature) dvmObject;
                    return new ByteArray(sig.toByteArray());
                }
            }
        }
        return vm.jni.callObjectMethod(vm, dvmObject, signature, methodName, args, varArg);
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
                return new StringObject(vm, ((DvmClass) dvmObject).getClassName().replace('/', '.'));
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
            case "android/app/Application->getPackageManager()Landroid/content/pm/PackageManager;":
                DvmClass clazz = vm.resolveClass("android/content/pm/PackageManager");
                return clazz.newObject(signature);
            case "android/content/pm/PackageManager->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;": {
                StringObject packageName = vaList.getObject(0);
                int flags = vaList.getInt(4);
                if (log.isDebugEnabled()) {
                    log.debug("getPackageInfo packageName=" + packageName.getValue() + ", flags=0x" + Integer.toHexString(flags));
                }
                return new PackageInfo(vm, packageName.value, flags);
            }
            case "android/app/Application->getPackageName()Ljava/lang/String;": {
                String packageName = vm.getPackageName();
                if (packageName != null) {
                    return new StringObject(vm, packageName);
                }
            }
            case "android/content/pm/Signature->toByteArray()[B":
                if (dvmObject instanceof Signature) {
                    Signature sig = (Signature) dvmObject;
                    return new ByteArray(sig.toByteArray());
                }
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
            case "android/content/pm/Signature->hashCode()I": {
                if (dvmObject instanceof Signature) {
                    Signature sig = (Signature) dvmObject;
                    return sig.getHashCode();
                }
            }
        }
        return vm.jni.callIntMethodV(vm, dvmObject, signature, methodName, args, vaList);
    }

    int callBooleanMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callBooleanMethodV signature=" + signature);
        }
        if ("java/util/Enumeration->hasMoreElements()Z".equals(signature)) {
            return ((Enumeration) dvmObject).hasMoreElements() ? VM.JNI_TRUE : VM.JNI_FALSE;
        }
        return dvmClass.vm.jni.callBooleanMethodV(dvmClass.vm, dvmObject, signature, methodName, args, vaList) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    int callIntMethod(DvmObject dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callIntMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        if ("java/lang/Integer->intValue()I".equals(signature)) {
            DvmInteger integer = (DvmInteger) dvmObject;
            return integer.value;
        }
        return vm.jni.callIntMethod(vm, dvmObject, signature, methodName, args, varArg);
    }

    void callVoidMethod(DvmObject dvmObject, VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callVoidMethod signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        vm.jni.callVoidMethod(vm, dvmObject, signature, methodName, args, varArg);
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

    int CallStaticBooleanMethod(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callStaticBooleanMethod signature=" + signature);
        }
        return dvmClass.vm.jni.callStaticBooleanMethod(signature, varArg) ? VM.JNI_TRUE : VM.JNI_FALSE;
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

    int newObject(VarArg varArg) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("newObject signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        switch (signature) {
            case "java/lang/String-><init>([B)V":
                ByteArray array = varArg.getObject(0);
                return dvmClass.vm.addObject(new StringObject(vm, new String(array.getValue())), false);
            case "java/lang/String-><init>([BLjava/lang/String;)V":
                array = varArg.getObject(0);
                StringObject string = varArg.getObject(1);
                try {
                    return dvmClass.vm.addObject(new StringObject(vm, new String(array.getValue(), string.getValue())), false);
                } catch (UnsupportedEncodingException e) {
                    throw new IllegalStateException(e);
                }
        }
        return dvmClass.vm.addObject(dvmClass.vm.jni.newObject(dvmClass, signature, varArg), false);
    }

    void callVoidMethodV(DvmObject dvmObject, VaList vaList) {
        String signature = dvmClass.getClassName() + "->" + methodName + args;
        if (log.isDebugEnabled()) {
            log.debug("callVoidMethodV signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        vm.jni.callVoidMethodV(vm, dvmObject, signature, methodName, args, vaList);
    }
}
