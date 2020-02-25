package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.linux.android.dvm.api.ClassLoader;
import com.github.unidbg.linux.android.dvm.api.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.linux.android.dvm.wrapper.DvmLong;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;

public abstract class AbstractJni implements Jni {

    private static final Log log = LogFactory.getLog(AbstractJni.class);

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
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
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        if ("android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;".equals(signature) &&
                dvmObject instanceof PackageInfo) {
            PackageInfo packageInfo = (PackageInfo) dvmObject;
            if (packageInfo.getPackageName().equals(vm.getPackageName())) {
                Signature[] signatures = vm.getSignatures();
                if (signatures != null) {
                    return new ArrayObject(signatures);
                }
            }
        }
        if ("android/content/pm/PackageInfo->versionName:Ljava/lang/String;".equals(signature) &&
                dvmObject instanceof PackageInfo) {
            PackageInfo packageInfo = (PackageInfo) dvmObject;
            if (packageInfo.getPackageName().equals(vm.getPackageName())) {
                String versionName = vm.getVersionName();
                if (versionName != null) {
                    return new StringObject(vm, versionName);
                }
            }
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public long callLongMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if ("java/lang/Long->longValue()J".equals(signature)) {
            DvmLong val = (DvmLong) dvmObject;
            return val.value;
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public float callFloatMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject<?> callObjectMethodA(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "android/app/Application->getAssets()Landroid/content/res/AssetManager;":
                return new AssetManager(vm, signature);
            case "android/app/Application->getClassLoader()Ljava/lang/ClassLoader;":
                return new ClassLoader(vm, signature);
            case "android/app/Application->getContentResolver()Landroid/content/ContentResolver;":
                return new DvmObject<>(vm.resolveClass("android/content/ContentResolver"), signature);
            case "java/util/ArrayList->get(I)Ljava/lang/Object;": {
                int index = vaList.getInt(0);
                ArrayListObject arrayList = (ArrayListObject) dvmObject;
                return arrayList.getValue().get(index);
            }
            case "android/app/Application->getSystemService(Ljava/lang/String;)Ljava/lang/Object;": {
                StringObject serviceName = vaList.getObject(0);
                assert serviceName != null;
                return new SystemService(vm, serviceName.getValue());
            }
            case "java/lang/String->toString()Ljava/lang/String;":
                return dvmObject;
            case "java/lang/Class->getName()Ljava/lang/String;":
                return new StringObject(vm, ((DvmClass) dvmObject).getName());
            case "android/view/accessibility/AccessibilityManager->getEnabledAccessibilityServiceList(I)Ljava/util/List;":
                return new ArrayListObject(vm, Collections.<DvmObject<?>>emptyList());
            case "java/util/Enumeration->nextElement()Ljava/lang/Object;":
                return ((Enumeration) dvmObject).nextElement();
            case "java/util/Locale->getLanguage()Ljava/lang/String;":
                Locale locale = (Locale) dvmObject.getValue();
                return new StringObject(vm, locale.getLanguage());
            case "java/util/Locale->getCountry()Ljava/lang/String;":
                locale = (Locale) dvmObject.getValue();
                return new StringObject(vm, locale.getCountry());
            case "android/os/IServiceManager->getService(Ljava/lang/String;)Landroid/os/IBinder;": {
                ServiceManager serviceManager = (ServiceManager) dvmObject;
                StringObject serviceName = vaList.getObject(0);
                assert serviceName != null;
                return serviceManager.getService(vm, serviceName.getValue());
            }
            case "java/io/File->getAbsolutePath()Ljava/lang/String;":
                File file = (File) dvmObject.getValue();
                return new StringObject(vm, file.getAbsolutePath());
            case "android/app/Application->getPackageManager()Landroid/content/pm/PackageManager;":
            case "android/content/ContextWrapper->getPackageManager()Landroid/content/pm/PackageManager;":
            case "android/content/Context->getPackageManager()Landroid/content/pm/PackageManager;":
                DvmClass clazz = vm.resolveClass("android/content/pm/PackageManager");
                return clazz.newObject(signature);
            case "android/content/pm/PackageManager->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;": {
                StringObject packageName = vaList.getObject(0);
                assert packageName != null;
                int flags = vaList.getInt(4);
                if (log.isDebugEnabled()) {
                    log.debug("getPackageInfo packageName=" + packageName.getValue() + ", flags=0x" + Integer.toHexString(flags));
                }
                return new PackageInfo(vm, packageName.value, flags);
            }
            case "android/app/Application->getPackageName()Ljava/lang/String;":
            case "android/content/ContextWrapper->getPackageName()Ljava/lang/String;":
            case "android/content/Context->getPackageName()Ljava/lang/String;": {
                String packageName = vm.getPackageName();
                if (packageName != null) {
                    return new StringObject(vm, packageName);
                }
                break;
            }
            case "android/content/pm/Signature->toByteArray()[B":
                if (dvmObject instanceof Signature) {
                    Signature sig = (Signature) dvmObject;
                    return new ByteArray(sig.toByteArray());
                }
                break;
            case "android/content/pm/Signature->toCharsString()Ljava/lang/String;":
                if (dvmObject instanceof Signature) {
                    Signature sig = (Signature) dvmObject;
                    return new StringObject(vm, sig.toCharsString());
                }
                break;
            case "java/lang/String->getBytes(Ljava/lang/String;)[B":
                String str = (String) dvmObject.getValue();
                StringObject charsetName = vaList.getObject(0);
                assert charsetName != null;
                try {
                    return new ByteArray(str.getBytes(charsetName.value));
                } catch (UnsupportedEncodingException e) {
                    throw new IllegalStateException(e);
                }
            case "java/security/cert/CertificateFactory->generateCertificate(Ljava/io/InputStream;)Ljava/security/cert/Certificate;":
                CertificateFactory factory = (CertificateFactory) dvmObject.value;
                DvmObject<?> stream = vaList.getObject(0);
                assert stream != null;
                InputStream inputStream = (InputStream) stream.value;
                try {
                    return new DvmObject<>(vm.resolveClass("java/security/cert/Certificate"), factory.generateCertificate(inputStream));
                } catch (CertificateException e) {
                    throw new IllegalStateException(e);
                }
            case "java/security/cert/Certificate->getEncoded()[B": {
                Certificate certificate = (Certificate) dvmObject.value;
                try {
                    return new ByteArray(certificate.getEncoded());
                } catch (CertificateEncodingException e) {
                    throw new IllegalStateException(e);
                }
            }
            case "java/security/MessageDigest->digest([B)[B": {
                MessageDigest messageDigest = (MessageDigest) dvmObject.value;
                ByteArray array = vaList.getObject(0);
                assert array != null;
                return new ByteArray(messageDigest.digest(array.value));
            }
            case "java/util/ArrayList->remove(I)Ljava/lang/Object;": {
                int index = vaList.getInt(0);
                ArrayListObject list = (ArrayListObject) dvmObject;
                return list.value.remove(index);
            }
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodA(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/android/internal/os/BinderInternal->getContextObject()Landroid/os/IBinder;":
                return new Binder(vm, signature);
            case "android/app/ActivityThread->currentActivityThread()Landroid/app/ActivityThread;":
                return new DvmObject<Object>(dvmClass, null);
            case "android/app/ActivityThread->currentApplication()Landroid/app/Application;":
                return new DvmObject<>(vm.resolveClass("android/app/Application", vm.resolveClass("android/content/ContextWrapper", vm.resolveClass("android/content/Context"))), signature);
            case "java/util/Locale->getDefault()Ljava/util/Locale;":
                return new DvmObject<>(dvmClass, Locale.getDefault());
            case "android/os/ServiceManagerNative->asInterface(Landroid/os/IBinder;)Landroid/os/IServiceManager;":
                return new ServiceManager(vm, signature);
            case "com/android/internal/telephony/ITelephony$Stub->asInterface(Landroid/os/IBinder;)Lcom/android/internal/telephony/ITelephony;":
                return vaList.getObject(0);
            case "java/security/cert/CertificateFactory->getInstance(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;": {
                StringObject type = vaList.getObject(0);
                assert type != null;
                try {
                    return new DvmObject<>(vm.resolveClass("java/security/cert/CertificateFactory"), CertificateFactory.getInstance(type.value));
                } catch (CertificateException e) {
                    throw new IllegalStateException(e);
                }
            }
            case "java/security/MessageDigest->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;": {
                StringObject type = vaList.getObject(0);
                assert type != null;
                try {
                    return new DvmObject<>(vm.resolveClass("java/security/MessageDigest"), MessageDigest.getInstance(type.value));
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalStateException(e);
                }
            }
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "android/os/Bundle->getInt(Ljava/lang/String;)I":
                Bundle bundle = (Bundle) dvmObject;
                StringObject key = vaList.getObject(0);
                assert key != null;
                return bundle.getInt(key.getValue());
            case "java/util/ArrayList->size()I":
                ArrayListObject list = (ArrayListObject) dvmObject;
                return list.size();
            case "android/content/pm/Signature->hashCode()I": {
                if (dvmObject instanceof Signature) {
                    Signature sig = (Signature) dvmObject;
                    return sig.getHashCode();
                }
                break;
            }
            case "java/lang/Integer->intValue()I": {
                DvmInteger integer = (DvmInteger) dvmObject;
                return integer.value;
            }
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public long callStaticLongMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if ("java/lang/Boolean->booleanValue()Z".equals(signature)) {
            DvmBoolean dvmBoolean = (DvmBoolean) dvmObject;
            return dvmBoolean.value;
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/util/Enumeration->hasMoreElements()Z":
                return ((Enumeration) dvmObject).hasMoreElements();
            case "java/util/ArrayList->isEmpty()Z":
                return ((ArrayListObject) dvmObject).isEmpty();
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void callStaticVoidMethodA(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject<?> dvmObject, String signature, DvmObject<?> value) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
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
    public DvmObject<?> newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "java/io/ByteArrayInputStream-><init>([B)V": {
                ByteArray array = vaList.getObject(0);
                assert array != null;
                return new DvmObject<>(vm.resolveClass("java/io/ByteArrayInputStream"), new ByteArrayInputStream(array.value));
            }
            case "java/lang/String-><init>([B)V": {
                ByteArray array = vaList.getObject(0);
                assert array != null;
                return new StringObject(vm, new String(array.value));
            }
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject<?> allocObject(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("java/util/HashMap->allocObject".equals(signature)) {
            return dvmClass.newObject(new HashMap<>());
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject<?> dvmObject, String signature, int value) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void setLongField(BaseVM vm, DvmObject<?> dvmObject, String signature, long value) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void setBooleanField(BaseVM vm, DvmObject<?> dvmObject, String signature, boolean value) {
        throw new AbstractMethodError(signature);
    }
    
    @Override
    public void setDoubleField(BaseVM vm, DvmObject<?> dvmObject, String signature, double value) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
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
            case "android/content/Context->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":
                return new ApplicationInfo(vm);
            case "android/content/Context->getPackageName()Ljava/lang/String;": {
                String packageName = vm.getPackageName();
                if (packageName != null) {
                    return new StringObject(vm, packageName);
                }
                break;
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
                break;
            }
            case "android/content/pm/Signature->toCharsString()Ljava/lang/String;": {
                if (dvmObject instanceof Signature) {
                    Signature sig = (Signature) dvmObject;
                    return new StringObject(vm, sig.toCharsString());
                }
                break;
            }
            case "java/lang/Class->getName()Ljava/lang/String;": {
                DvmClass clazz = (DvmClass) dvmObject;
                return new StringObject(vm, clazz.getName());
            }
            case "java/lang/String->getClass()Ljava/lang/Class;":
            case "java/lang/Integer->getClass()Ljava/lang/Class;": {
                return dvmObject.getObjectType();
            }
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if ("java/lang/Integer->intValue()I".equals(signature)) {
            DvmInteger integer = (DvmInteger) dvmObject;
            return integer.value;
        }

        throw new AbstractMethodError(signature);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void callVoidMethodA(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public void setStaticLongField(BaseVM vm, String signature, long value) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public long getStaticLongField(BaseVM vm, String signature) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public DvmObject<?> toReflectedMethod(BaseVM vm, String signature) {
        throw new AbstractMethodError(signature);
    }

    @Override
    public boolean acceptMethod(String signature, boolean isStatic) {
        return true;
    }

    @Override
    public boolean acceptField(String signature, boolean isStatic) {
        return true;
    }
}
