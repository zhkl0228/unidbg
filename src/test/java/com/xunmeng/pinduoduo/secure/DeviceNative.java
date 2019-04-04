package com.xunmeng.pinduoduo.secure;

import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.LibraryResolver;
import cn.banny.emulator.arm.ARMEmulator;
import cn.banny.emulator.linux.Module;
import cn.banny.emulator.linux.android.AndroidARMEmulator;
import cn.banny.emulator.linux.android.AndroidResolver;
import cn.banny.emulator.linux.android.dvm.*;
import cn.banny.emulator.memory.Memory;
import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.UUID;
import java.util.zip.GZIPOutputStream;

public class DeviceNative extends AbstractJni {

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(23);
    }

    private static ARMEmulator createARMEmulator() {
        return new AndroidARMEmulator("com.xunmeng.pinduoduo");
    }

    private final ARMEmulator emulator;
    private final VM vm;
    private final Module module;

    private final DvmClass DeviceNative;

    private DeviceNative() throws IOException {
        emulator = createARMEmulator();
        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(null);
        DalvikModule dm = vm.loadLibrary(new File("src/test/resources/example_binaries/libpdd_secure.so"), false);
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();

        DeviceNative = vm.resolveClass("com/xunmeng/pinduoduo/secure/DeviceNative");
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("destroy module=" + module);
    }

    public static void main(String[] args) throws Exception {
        DeviceNative test = new DeviceNative();

        test.info2();

        test.destroy();
    }

    private void info2() {
        vm.setJni(this);

        /*emulator.attach(module.base, module.base + module.size).addBreakPoint(module, 0x00099422);
        emulator.traceRead(0xbffff6bcL, 0xbffff6bcL + 16);
        emulator.traceWrite(0xbffff6ccL, 0xbffff6ccL + 16);*/

        System.out.println(UUID.randomUUID().toString());
        long start = System.currentTimeMillis();
        Number ret = DeviceNative.callStaticJniMethod(emulator, "info2(Landroid/content/Context;J)Ljava/lang/String;", vm.resolveClass("android/content/Context").newObject(null), 1554297323913L);
        long hash = ret.intValue() & 0xffffffffL;
        StringObject obj = vm.getObject(hash);
        vm.deleteLocalRefs();
        System.err.println(obj.getValue());
        Inspector.inspect(Base64.decodeBase64(obj.getValue()), "info2 ret=" + ret + ", obj=" + obj.getValue() + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    private static final String ANDROID_ID = "android_id";

    @Override
    public DvmObject getStaticObjectField(VM vm, DvmClass dvmClass, String signature) {
        switch (signature) {
            case "android/os/Build->SERIAL:Ljava/lang/String;":
                return new StringObject(vm, "05efc1db004d1dee");
            case "android/provider/Settings$Secure->ANDROID_ID:Ljava/lang/String;":
                return new StringObject(vm, ANDROID_ID);
        }

        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public DvmObject callObjectMethod(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VarArg varArg) {
        switch (signature) {
            case "android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;":
                DvmClass clazz = vm.resolveClass("android/telephony/TelephonyManager");
                return clazz.newObject(null);
            case "android/telephony/TelephonyManager->getDeviceId()Ljava/lang/String;":
                return new StringObject(vm, "353490069873368");
            case "android/telephony/TelephonyManager->getSimSerialNumber()Ljava/lang/String;":
                return new StringObject(vm, "89860112851083069510");
            case "android/telephony/TelephonyManager->getSimOperatorName()Ljava/lang/String;":
                return new StringObject(vm, "");
            case "android/telephony/TelephonyManager->getSimCountryIso()Ljava/lang/String;":
                return new StringObject(vm, "cn");
            case "android/telephony/TelephonyManager->getSubscriberId()Ljava/lang/String;":
                return new StringObject(vm, "460013061600183");
            case "android/telephony/TelephonyManager->getNetworkOperator()Ljava/lang/String;":
                return new StringObject(vm, "46001");
            case "android/telephony/TelephonyManager->getNetworkOperatorName()Ljava/lang/String;":
                return new StringObject(vm, "中国联通");
            case "android/telephony/TelephonyManager->getNetworkCountryIso()Ljava/lang/String;":
                return new StringObject(vm, "cn");
            case "android/content/Context->getContentResolver()Landroid/content/ContentResolver;":
                clazz = vm.resolveClass("android/content/ContentResolver");
                return clazz.newObject(null);
            case "java/lang/Throwable->getStackTrace()[Ljava/lang/StackTraceElement;":
                StackTraceElement[] elements = Thread.currentThread().getStackTrace();
                DvmObject[] objs = new DvmObject[elements.length];
                for (int i = 0; i < elements.length; i++) {
                    objs[i] = new DvmObject<>(vm.resolveClass("java/lang/StackTraceElement"), elements[i]);
                }
                return new ArrayObject(objs);
            case "java/lang/StackTraceElement->getClassName()Ljava/lang/String;":
                StackTraceElement element = (StackTraceElement) dvmObject.getValue();
                return new StringObject(vm, element.getClassName());
            case "java/io/ByteArrayOutputStream->toByteArray()[B":
                ByteArrayOutputStream baos = (ByteArrayOutputStream) dvmObject.getValue();
                byte[] data = baos.toByteArray();
                // Inspector.inspect(data, "java/io/ByteArrayOutputStream->toByteArray()");
                return new ByteArray(data);
        }

        return super.callObjectMethod(vm, dvmObject, signature, methodName, args, varArg);
    }

    @Override
    public DvmObject callStaticObjectMethod(VM vm, DvmClass dvmClass, String signature, String methodName, String args, VarArg varArg) {
        if ("android/provider/Settings$Secure->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;".equals(signature)) {
            StringObject key = varArg.getObject(1);

            if (ANDROID_ID.equals(key.getValue())) {
                return new StringObject(vm, "21ad4f5b0bc1b14b");
            } else {
                System.out.println("android/provider/Settings$Secure->getString key=" + key.getValue());
            }
        }

        return super.callStaticObjectMethod(vm, dvmClass, signature, methodName, args, varArg);
    }

    private static final int PHONE_TYPE_GSM = 1;

    /** SIM card state: Ready */
    private static final int SIM_STATE_READY = 5;

    /** Current network is LTE */
    private static final int NETWORK_TYPE_LTE = 13;

    /** Data connection state: Connected. IP traffic should be available. */
    private static final int DATA_CONNECTED      = 2;

    /** Data connection activity: No traffic. */
    private static final int DATA_ACTIVITY_NONE = 0x00000000;

    @Override
    public int callIntMethod(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VarArg varArg) {
        switch (signature) {
            case "android/telephony/TelephonyManager->getPhoneType()I":
                return PHONE_TYPE_GSM;
            case "android/telephony/TelephonyManager->getSimState()I":
                return SIM_STATE_READY;
            case "android/telephony/TelephonyManager->getNetworkType()I":
                return NETWORK_TYPE_LTE;
            case "android/telephony/TelephonyManager->getDataState()I":
                return DATA_CONNECTED;
            case "android/telephony/TelephonyManager->getDataActivity()I":
                return DATA_ACTIVITY_NONE;
        }

        return super.callIntMethod(vm, dvmObject, signature, methodName, args, varArg);
    }

    @Override
    public int getStaticIntField(DvmClass dvmClass, String signature) {
        if ("android/telephony/TelephonyManager->PHONE_TYPE_GSM:I".equals(signature)) {
            return PHONE_TYPE_GSM;
        }

        return super.getStaticIntField(dvmClass, signature);
    }

    @Override
    public boolean callStaticBooleanMethod(String signature, VarArg varArg) {
        if ("android/os/Debug->isDebuggerConnected()Z".equals(signature)) {
            return false;
        }

        return super.callStaticBooleanMethod(signature, varArg);
    }

    @Override
    public DvmObject newObject(DvmClass clazz, String signature, VarArg varArg) {
        switch (signature) {
            case "java/lang/Throwable-><init>()V":
                return clazz.newObject(null);
            case "java/io/ByteArrayOutputStream-><init>()V":
                return clazz.newObject(new ByteArrayOutputStream());
            case "java/util/zip/GZIPOutputStream-><init>(Ljava/io/OutputStream;)V":
                DvmObject obj = varArg.getObject(0);
                OutputStream outputStream = (OutputStream) obj.getValue();
                try {
                    return clazz.newObject(new GZIPOutputStream(outputStream));
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
        }

        return super.newObject(clazz, signature, varArg);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VarArg varArg) {
        switch (signature) {
            case "java/util/zip/GZIPOutputStream->write([B)V":
                OutputStream outputStream = (OutputStream) dvmObject.getValue();
                ByteArray array = varArg.getObject(0);
                // Inspector.inspect(array.getValue(), "java/util/zip/GZIPOutputStream->write outputStream=" + outputStream.getClass().getName());
                try {
                    outputStream.write(array.getValue());
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
                return;
            case "java/util/zip/GZIPOutputStream->finish()V":
                GZIPOutputStream gzipOutputStream = (GZIPOutputStream) dvmObject.getValue();
                try {
                    gzipOutputStream.finish();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
                return;
            case "java/util/zip/GZIPOutputStream->close()V":
                gzipOutputStream = (GZIPOutputStream) dvmObject.getValue();
                try {
                    gzipOutputStream.close();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
                return;
        }

        super.callVoidMethod(vm, dvmObject, signature, methodName, args, varArg);
    }

    @Override
    public DvmObject callStaticObjectMethodV(VM vm, DvmClass dvmClass, String signature, String methodName, String args, VaList vaList) {
        if ("java/util/UUID->randomUUID()Ljava/util/UUID;".equals(signature)) {
            return dvmClass.newObject(UUID.randomUUID());
        }

        return super.callStaticObjectMethodV(vm, dvmClass, signature, methodName, args, vaList);
    }

    @Override
    public DvmObject callObjectMethodV(VM vm, DvmObject dvmObject, String signature, String methodName, String args, VaList vaList) {
        switch (signature) {
            case "java/util/UUID->toString()Ljava/lang/String;":
                UUID uuid = (UUID) dvmObject.getValue();
                return new StringObject(vm, uuid.toString());
            case "java/lang/String->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;":
                StringObject str = (StringObject) dvmObject;
                StringObject s1 = vaList.getObject(0);
                StringObject s2 = vaList.getObject(4);
                return new StringObject(vm, str.getValue().replaceAll(s1.getValue(), s2.getValue()));
        }

        return super.callObjectMethodV(vm, dvmObject, signature, methodName, args, vaList);
    }
}
