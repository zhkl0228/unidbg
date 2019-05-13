package cn.banny.emulator.linux.android.dvm;

import cn.banny.emulator.linux.android.dvm.api.PackageInfo;
import cn.banny.emulator.linux.android.dvm.api.Signature;
import cn.banny.emulator.linux.android.dvm.api.SystemService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class DvmField implements Hashable {

    private static final Log log = LogFactory.getLog(DvmField.class);

    private final DvmClass dvmClass;
    private final String fieldName;
    private final String fieldType;

    DvmField(DvmClass dvmClass, String fieldName, String fieldType) {
        this.dvmClass = dvmClass;
        this.fieldName = fieldName;
        this.fieldType = fieldType;
    }

    int getStaticObjectField() {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getStaticObjectField dvmClass=" + dvmClass + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        switch (signature) {
            case "android/content/Context->TELEPHONY_SERVICE:Ljava/lang/String;":
                return vm.addObject(new StringObject(vm, SystemService.TELEPHONY_SERVICE), false);
            case "android/content/Context->WIFI_SERVICE:Ljava/lang/String;":
                return vm.addObject(new StringObject(vm, SystemService.WIFI_SERVICE), false);
            case "android/content/Context->CONNECTIVITY_SERVICE:Ljava/lang/String;":
                return vm.addObject(new StringObject(vm, SystemService.CONNECTIVITY_SERVICE), false);
            case "android/content/Context->ACCESSIBILITY_SERVICE:Ljava/lang/String;":
                return vm.addObject(new StringObject(vm, SystemService.ACCESSIBILITY_SERVICE), false);
            case "android/content/Context->KEYGUARD_SERVICE:Ljava/lang/String;":
                return vm.addObject(new StringObject(vm, SystemService.KEYGUARD_SERVICE), false);
            case "android/content/Context->ACTIVITY_SERVICE:Ljava/lang/String;":
                return vm.addObject(new StringObject(vm, SystemService.ACTIVITY_SERVICE), false);
            case "java/lang/Void->TYPE:Ljava/lang/Class;":
                return vm.addObject(vm.resolveClass("java/lang/Void"), false);
            case "java/lang/Boolean->TYPE:Ljava/lang/Class;":
                return vm.addObject(vm.resolveClass("java/lang/Boolean"), false);
            case "java/lang/Byte->TYPE:Ljava/lang/Class;":
                return vm.addLocalObject(vm.resolveClass("java/lang/Byte"));
            case "java/lang/Character->TYPE:Ljava/lang/Class;":
                return vm.addLocalObject(vm.resolveClass("java/lang/Character"));
            case "java/lang/Short->TYPE:Ljava/lang/Class;":
                return vm.addLocalObject(vm.resolveClass("java/lang/Short"));
            case "java/lang/Integer->TYPE:Ljava/lang/Class;":
                return vm.addLocalObject(vm.resolveClass("java/lang/Integer"));
            case "java/lang/Long->TYPE:Ljava/lang/Class;":
                return vm.addLocalObject(vm.resolveClass("java/lang/Long"));
            case "java/lang/Float->TYPE:Ljava/lang/Class;":
                return vm.addLocalObject(vm.resolveClass("java/lang/Float"));
            case "java/lang/Double->TYPE:Ljava/lang/Class;":
                return vm.addLocalObject(vm.resolveClass("java/lang/Double"));
        }

        DvmObject object = vm.jni.getStaticObjectField(vm, dvmClass, signature);
        return vm.addObject(object, false);
    }

    int getStaticIntField() {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getStaticIntField dvmClass=" + dvmClass + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        return dvmClass.vm.jni.getStaticIntField(dvmClass, signature);
    }

    int getObjectField(DvmObject dvmObject) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getObjectField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        BaseVM vm = dvmClass.vm;
        if ("android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;".equals(signature) &&
                dvmObject instanceof PackageInfo) {
            PackageInfo packageInfo = (PackageInfo) dvmObject;
            if (packageInfo.getPackageName().equals(vm.getPackageName())) {
                Signature[] signatures = vm.getSignatures();
                if (signatures != null) {
                    return vm.addObject(new ArrayObject(signatures), false);
                }
            }
        }
        return vm.addObject(vm.jni.getObjectField(vm, dvmObject, signature), false);
    }

    int getIntField(DvmObject dvmObject) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getIntField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        return dvmClass.vm.jni.getIntField(dvmClass.vm, dvmObject, signature);
    }

    void setObjectField(DvmObject dvmObject, DvmObject value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setObjectField fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        dvmClass.vm.jni.setObjectField(dvmClass.vm, dvmObject, signature, value);
    }

    int getBooleanField(DvmObject dvmObject) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("getBooleanField dvmObject=" + dvmObject + ", fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature);
        }
        return dvmClass.vm.jni.getBooleanField(dvmClass.vm, dvmObject, signature) ? VM.JNI_TRUE : VM.JNI_FALSE;
    }

    void setIntField(DvmObject dvmObject, int value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setIntField fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        dvmClass.vm.jni.setIntField(dvmClass.vm, dvmObject, signature, value);
    }

    void setLongField(DvmObject dvmObject, long value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setLongField fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        dvmClass.vm.jni.setLongField(dvmClass.vm, dvmObject, signature, value);
    }

    void setBooleanField(DvmObject dvmObject, boolean value) {
        String signature = dvmClass.getClassName() + "->" + fieldName + ":" + fieldType;
        if (log.isDebugEnabled()) {
            log.debug("setBooleanField fieldName=" + fieldName + ", fieldType=" + fieldType + ", signature=" + signature + ", value=" + value);
        }
        dvmClass.vm.jni.setBooleanField(dvmClass.vm, dvmObject, signature, value);
    }
}
