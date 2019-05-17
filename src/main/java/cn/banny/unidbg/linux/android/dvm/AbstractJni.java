package cn.banny.unidbg.linux.android.dvm;

import cn.banny.unidbg.linux.android.dvm.api.*;
import cn.banny.unidbg.linux.android.dvm.wrapper.DvmInteger;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.Locale;

public abstract class AbstractJni implements Jni {

    private static final Log log = LogFactory.getLog(AbstractJni.class);

    @Override
    public DvmObject getStaticObjectField(VM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "android/content/Context->TELEPHONY_SERVICE:Ljava/lang/String;":
                return new StringObject(vm, SystemService.TELEPHONY_SERVICE);
            case "android/content/Context->WIFI_SERVICE:Ljava/lang/String;":
                return new StringObject(vm, SystemService.WIFI_SERVICE);
            case "android/content/Context->CONNECTIVITY_SERVICE:Ljava/lang/String;":
                return new StringObject(vm, SystemService.CONNECTIVITY_SERVICE);
            case "android/content/Context->ACCESSIBILITY_SERVICE:Ljava/lang/String;":
                return new StringObject(vm, SystemService.ACCESSIBILITY_SERVICE);
            case "android/content/Context->KEYGUARD_SERVICE:Ljava/lang/String;":
                return new StringObject(vm, SystemService.KEYGUARD_SERVICE);
            case "android/content/Context->ACTIVITY_SERVICE:Ljava/lang/String;":
                return new StringObject(vm, SystemService.ACTIVITY_SERVICE);
            case "java/lang/Void->TYPE:Ljava/lang/Class;":
                return vm.resolveClass("java/lang/Void");
            case "java/lang/Boolean->TYPE:Ljava/lang/Class;":
                return vm.resolveClass("java/lang/Boolean");
            case "java/lang/Byte->TYPE:Ljava/lang/Class;":
                return vm.resolveClass("java/lang/Byte");
            case "java/lang/Character->TYPE:Ljava/lang/Class;":
                return vm.resolveClass("java/lang/Character");
            case "java/lang/Short->TYPE:Ljava/lang/Class;":
                return vm.resolveClass("java/lang/Short");
            case "java/lang/Integer->TYPE:Ljava/lang/Class;":
                return vm.resolveClass("java/lang/Integer");
            case "java/lang/Long->TYPE:Ljava/lang/Class;":
                return vm.resolveClass("java/lang/Long");
            case "java/lang/Float->TYPE:Ljava/lang/Class;":
                return vm.resolveClass("java/lang/Float");
            case "java/lang/Double->TYPE:Ljava/lang/Class;":
                return vm.resolveClass("java/lang/Double");
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public int getStaticIntField(DvmClass dvmClass, String signature) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject getObjectField(VM vm, DvmObject dvmObject, String signature) {
        if ("android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;".equals(signature) &&
                dvmObject instanceof PackageInfo) {
            PackageInfo packageInfo = (PackageInfo) dvmObject;
            if (packageInfo.getPackageName().equals(vm.getPackageName())) {
                BaseVM bvm = (BaseVM) vm;
                Signature[] signatures = bvm.getSignatures();
                if (signatures != null) {
                    return new ArrayObject(signatures);
                }
            }
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public boolean callStaticBooleanMethod(String signature, VarArg varArg) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public boolean callStaticBooleanMethodV(String signature) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public int callStaticIntMethodV(String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject callObjectMethodV(VM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList) {
        switch (signature) {
            case "android/app/Application->getAssets()Landroid/content/res/AssetManager;":
                return new AssetManager(vm.resolveClass("android/content/res/AssetManager"), signature);
            case "android/app/Application->getClassLoader()Ljava/lang/ClassLoader;":
                return new cn.banny.unidbg.linux.android.dvm.api.ClassLoader(vm.resolveClass("dalvik/system/PathClassLoader"), signature);
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
            case "android/content/Context->getPackageManager()Landroid/content/pm/PackageManager;":
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
            case "android/app/Application->getPackageName()Ljava/lang/String;":
            case "android/content/Context->getPackageName()Ljava/lang/String;": {
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

        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject callStaticObjectMethod(VM vm, DvmClass dvmClass, String signature, String methodName, String args, VarArg varArg) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject callStaticObjectMethodV(VM vm, DvmClass dvmClass, String signature, String methodName, String args, VaList vaList) {
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

        throw new AbstractMethodError(signature);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList) {
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

        throw new AbstractMethodError(signature);
    }

    @Override
    public long callStaticLongMethodV(String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList) {
        if ("java/util/Enumeration->hasMoreElements()Z".equals(signature)) {
            return ((Enumeration) dvmObject).hasMoreElements();
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject dvmObject, String signature) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void callStaticVoidMethodV(String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject dvmObject, String signature, DvmObject value) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject dvmObject, String signature) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject newObject(DvmClass clazz, String signature, VarArg varArg) {
        BaseVM vm = clazz.vm;
        switch (signature) {
            case "java/lang/String-><init>([B)V":
                ByteArray array = varArg.getObject(0);
                return new StringObject(vm, new String(array.getValue()));
            case "java/lang/String-><init>([BLjava/lang/String;)V":
                array = varArg.getObject(0);
                StringObject string = varArg.getObject(1);
                try {
                    return new StringObject(vm, new String(array.getValue(), string.getValue()));
                } catch (UnsupportedEncodingException e) {
                    throw new IllegalStateException(e);
                }
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject newObjectV(DvmClass clazz, String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject dvmObject, String signature, int value) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void setLongField(BaseVM vm, DvmObject dvmObject, String signature, long value) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void setBooleanField(BaseVM vm, DvmObject dvmObject, String signature, boolean value) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject callObjectMethod(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VarArg varArg) {
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

        throw new AbstractMethodError(signature);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VarArg varArg) {
        if ("java/lang/Integer->intValue()I".equals(signature)) {
            DvmInteger integer = (DvmInteger) dvmObject;
            return integer.value;
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VarArg varArg) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList) {
        throw new AbstractMethodError(signature);
    }
}
