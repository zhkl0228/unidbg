package com.didi.security.wireless;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.arm.HookStatus;
import cn.banny.unidbg.arm.context.EditableArm32RegisterContext;
import cn.banny.unidbg.file.FileIO;
import cn.banny.unidbg.file.IOResolver;
import cn.banny.unidbg.hook.ReplaceCallback;
import cn.banny.unidbg.hook.hookzz.HookZz;
import cn.banny.unidbg.hook.hookzz.IHookZz;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.android.dvm.*;
import cn.banny.unidbg.linux.android.dvm.api.SystemService;
import cn.banny.unidbg.linux.android.dvm.array.ByteArray;
import cn.banny.unidbg.linux.file.ByteArrayFileIO;
import cn.banny.unidbg.linux.file.SimpleFileIO;
import cn.banny.unidbg.memory.Memory;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.*;
import java.net.*;


public class SecurityLib extends AbstractJni implements IOResolver {

    private static final int WSG_CODE_OK = 0;

    private static final String APP_PACKAGE_NAME = "com.sdu.didi.psnger";

    private final ARMEmulator emulator;
    private final VM vm;
    private final DvmClass SecurityLib;

    private static final String APK_PATH = "src/test/resources/app/com.sdu.didi.psnger.apk";

    private final Module module;

    private SecurityLib() throws IOException {
        emulator = new AndroidARMEmulator(APP_PACKAGE_NAME);
        emulator.getSyscallHandler().addIOResolver(this);
        System.out.println("== init ===");

        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(new File(APK_PATH));


        vm.setJni(this);
        DalvikModule dm = vm.loadLibrary("didiwsg", false);

        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();

        SecurityLib = vm.resolveClass("com/didi/security/wireless/SecurityLib");

        IHookZz hookZz = HookZz.getInstance(emulator);
        hookZz.replace(module.base + 0x000733A0 + 1, new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                long currentTimeMillis = System.currentTimeMillis();
                EditableArm32RegisterContext context = emulator.getContext();
                context.setR1((int) currentTimeMillis);
                return HookStatus.LR(emulator, (int) (currentTimeMillis >> 32));
            }
        });

        Logger.getLogger("cn.banny.unidbg.AbstractEmulator").setLevel(Level.DEBUG);
        DvmObject context = vm.resolveClass("android/content/Context").newObject(null);
        Number ret = SecurityLib.callStaticJniMethod(emulator, "nativeInit(Landroid/content/Context;)I",
                context);
        vm.deleteLocalRefs();
        if (ret.intValue() != WSG_CODE_OK) {
            throw new IllegalStateException("nativeInit ret=" + ret.intValue());
        }

//        emulator.getMemory().runLastThread(TimeUnit.SECONDS.toMicros(3));

//        emulator.traceCode();
//        emulator.attach().addBreakPoint(module, 0x000734A0);
        emulator.getMemory().runThread(1, 0);

//        emulator.attach().debug(emulator);
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("module=" + module);
        System.out.println("== destroy ===");
    }

    public static void main(String[] args) throws Exception {
        com.didi.security.wireless.SecurityLib test = new SecurityLib();
        test.sign();
        test.destroy();
    }

    private void sign() {
        String str = "123456";

//        emulator.traceCode();
        DvmObject context = vm.resolveClass("android/content/Context").newObject(null);
        long timestamp = System.currentTimeMillis();
        Number ret = SecurityLib.callStaticJniMethod(emulator, "nativeSig(Landroid/content/Context;JLjava/lang/String;[B)Ljava/lang/String;",
                context,
                0, (int) timestamp, (int) (timestamp >> 32), // 一个long占两个int，所以要放两个寄存器，R0, R1, R2被占用，只剩R3的时候则组成long的两个int都放堆栈
                vm.addLocalObject(new StringObject(vm, "15058968156")),
                vm.addLocalObject(new ByteArray(str.getBytes())));

        long hash = ret.intValue() & 0xffffffffL;
        StringObject obj = vm.getObject(hash);
        vm.deleteLocalRefs();
        System.out.println(obj.toString());
    }

    @Override
    public FileIO resolve(File workDir, String pathname, int oflags) {
        switch (pathname) {
            case INSTALL_PATH:
                return new SimpleFileIO(oflags, new File(APK_PATH), pathname);
            case "/sys/block/mmcblk0/device/type":
                return new ByteArrayFileIO(oflags, pathname, "2".getBytes());
        }
        return null;
    }

    private static final String INSTALL_PATH = "/data/app/com.sdu.didi.psnger-1.apk";

    @Override
    public DvmObject callObjectMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        switch (signature) {
            case "android/content/Context->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;":
                return vm.resolveClass("android/content/SharedPreferences").newObject(null);
            case "android/content/SharedPreferences->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;": {
                StringObject name = varArg.getObject(0);
                StringObject defValue = varArg.getObject(1);
                System.err.println("android/content/SharedPreferences->getString name=" + name.getValue() + ", defValue=" + defValue.getValue());
                if ("wsg_conf".equals(name.getValue())) {
                    return new StringObject(vm, "mZUzsjDkxAqS/YFujbRrX3j/7jhZYgh8GHHqMzMdK9hXjXJ0lBEDsIFuKTfF48ps5gvaplUOkcmLNP5/FEmaqO4oUAad1HzDTQBZobDMeFpub20K+axGeu7PBZ+TztfPdVpMgVfmuHc7/axEHlZFBxadprthaQQtBfjzn2pf7Bp3RcreGaqnfO+QwENoQnpVo8Jj1CFy9vUnD8UDq4nO5S2ivoecc+g1luF9lLs5+4j1uCPK4QjSNhWp2HODbohlx01+uXQpMW1HVc0hjvEk/c8oKxFSJkqo8yZTpJ0Fg4lGc7f8znArzH1X6WanJIfA6O/XR/aUdAoAx9jHcC3QJM2kyM/F/aZB/7I0n5hWWwptaZfWf1nVxQMJrRzZ/X5bPEPCh+1czaeYVwZgEMfgLqo+yfGY8j0exLyd5vQnG4bIAV61X9P03+MXe4M67XmFaS0SsK3PuOYF5ht5I906QqXbcJcjF2YlkvnIC1UAJ70+MSKBLZErujU1GOBnPLLCyBt3PdzBNuwTVchZFPPcKYG7ZR5YEzpTNdxcu06Q8frtapYUus8rS7fHTbvUebdoR3oYDbe6hvzQX9E0Kq2YXOoByfy03I0/hSLW1GP+XYr2UIljf+9DaQxuZ4Qqk3p/PKh1QKlPL+bqC2jZhb1wLP4Vcg+unx/+diKBQsxVdW//J77vfUjj/1icJGrjbxHSUa4PB/YtfMFDfcPUAUOLvRWYyimyE3tvBUUs/RoFKMMFrvrzwIV9B+3oT/L292xdxa4U65DVHR1vULHWgxqW4HXOI9wBxh3GP5F9ZUDAHGjMQqjzaeV/w5LyscAJpsYpCWk9CTI4ixHpk5AvKRNNvq3z/SPZGPy+J0GkUbqT+gTsFyI370Levy3WHXoJxFZ3t2mgsyY1VS8rdbIh8rX5jdq0iGfIVw6D5pqRuhyz5Sgzoc45MJQCcXEniCrr5v4BkAafMybg7uRedFbqza1l1w==");
                }
            }
            case "android/content/Context->getPackageCodePath()Ljava/lang/String;":
                return new StringObject(vm, INSTALL_PATH);
            case "android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;":
                StringObject serviceName = varArg.getObject(0);
                System.err.println("android/content/Context->getSystemService name=" + serviceName);
                return new SystemService(vm, serviceName.getValue());
            case "android/telephony/TelephonyManager->getDeviceId()Ljava/lang/String;":
                return new StringObject(vm, "353490069873368");
            case "java/net/URL->openConnection(Ljava/net/Proxy;)Ljava/net/URLConnection;":
                Proxy proxy = (Proxy) varArg.getObject(0).getValue();
                URL url = (URL) dvmObject.getValue();
                try {
                    return vm.resolveClass("java/net/HttpURLConnection").newObject(url.openConnection(proxy));
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            case "java/net/HttpURLConnection->getOutputStream()Ljava/io/OutputStream;": {
                HttpURLConnection connection = (HttpURLConnection) dvmObject.getValue();
                try {
                    return vm.resolveClass("java/io/OutputStream").newObject(connection.getOutputStream());
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
            case "java/lang/String->getBytes()[B": {
                String str = (String) dvmObject.getValue();
                System.err.println("java/lang/String->getBytes str=" + str);
                return new ByteArray(str.getBytes());
            }
            case "java/net/HttpURLConnection->getInputStream()Ljava/io/InputStream;": {
                HttpURLConnection connection = (HttpURLConnection) dvmObject.getValue();
                try {
                    return vm.resolveClass("java/io/InputStream").newObject(connection.getInputStream());
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
            case "java/io/BufferedReader->readLine()Ljava/lang/String;": {
                BufferedReader reader = (BufferedReader) dvmObject.getValue();
                try {
                    String line = reader.readLine();
                    if (line != null) {
                        System.err.println("java/io/BufferedReader->readLine " + line);
                    }
                    return line == null ? null : new StringObject(vm, line);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            case "android/content/SharedPreferences->edit()Landroid/content/SharedPreferences$Editor;": {
                return vm.resolveClass("android/content/SharedPreferences$Editor").newObject(null);
            }
            case "android/content/SharedPreferences$Editor->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;": {
                StringObject name = varArg.getObject(0);
                StringObject value = varArg.getObject(1);
                System.err.println("android/content/SharedPreferences$Editor->putString name=" + name.getValue() + ", value=" + value.getValue());
                return dvmObject;
            }
        }
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }
    @Override
    public DvmObject newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
            case "java/net/URL-><init>(Ljava/lang/String;)V":
                StringObject url = varArg.getObject(0);
                System.err.println("open URL: " + url.getValue());
                try {
                    return vm.resolveClass("java/net/URL").newObject(new URL(url.getValue()));
                } catch (MalformedURLException e) {
                    throw new IllegalStateException(e);
                }
            case "java/io/InputStreamReader-><init>(Ljava/io/InputStream;)V": {
                InputStream inputStream = (InputStream) varArg.getObject(0).getValue();
                return vm.resolveClass("java/io/InputStreamReader").newObject(new InputStreamReader(inputStream));
            }
            case "java/io/BufferedReader-><init>(Ljava/io/Reader;)V": {
                Reader reader = (Reader) varArg.getObject(0).getValue();
                return vm.resolveClass("java/io/BufferedReader").newObject(new BufferedReader(reader));
            }
        }

        return super.newObject(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        if ("java/net/Proxy->NO_PROXY:Ljava/net/Proxy;".equals(signature)) {
            return vm.resolveClass("java/net/Proxy").newObject(Proxy.NO_PROXY);
        }

        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        switch (signature) {
            case "java/net/HttpURLConnection->setRequestMethod(Ljava/lang/String;)V": {
                HttpURLConnection connection = (HttpURLConnection) dvmObject.getValue();
                StringObject method = varArg.getObject(0);
                System.err.println("java/net/HttpURLConnection->setRequestMethod method=" + method.getValue());
                try {
                    connection.setRequestMethod(method.getValue());
                } catch (ProtocolException e) {
                    throw new IllegalStateException(e);
                }
                return;
            }
            case "java/net/HttpURLConnection->setConnectTimeout(I)V": {
                HttpURLConnection connection = (HttpURLConnection) dvmObject.getValue();
                int timeout = varArg.getInt(0);
                System.err.println("java/net/HttpURLConnection->setConnectTimeout timeout=" + timeout);
                connection.setConnectTimeout(timeout);
                return;
            }
            case "java/net/HttpURLConnection->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V": {
                HttpURLConnection connection = (HttpURLConnection) dvmObject.getValue();
                StringObject key = varArg.getObject(0);
                StringObject value = varArg.getObject(1);
                System.err.println("java/net/HttpURLConnection->setRequestProperty key=" + key.getValue() + ", value=" + value.getValue());
                connection.setRequestProperty(key.getValue(), value.getValue());
                return;
            }
            case "java/net/HttpURLConnection->setDoOutput(Z)V": {
                HttpURLConnection connection = (HttpURLConnection) dvmObject.getValue();
                int doOutput = varArg.getInt(0);
                System.err.println("java/net/HttpURLConnection->setDoOutput: " + doOutput);
                connection.setDoOutput(doOutput != 0);
                return;
            }
            case "java/io/OutputStream->write([B)V": {
                OutputStream outputStream = (OutputStream) dvmObject.getValue();
                ByteArray array = varArg.getObject(0);
                try {
                    outputStream.write(array.getValue());
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
                return;
            }
            case "java/io/OutputStream->close()V": {
                OutputStream outputStream = (OutputStream) dvmObject.getValue();
                try {
                    outputStream.close();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
                return;
            }
            case "java/net/HttpURLConnection->connect()V": {
                HttpURLConnection connection = (HttpURLConnection) dvmObject.getValue();
                try {
                    connection.connect();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
                return;
            }
            case "java/io/InputStream->close()V": {
                InputStream inputStream = (InputStream) dvmObject.getValue();
                try {
                    inputStream.close();
                    return;
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
            case "java/io/BufferedReader->close()V": {
                BufferedReader reader = (BufferedReader) dvmObject.getValue();
                try {
                    reader.close();
                    return;
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
            case "java/net/HttpURLConnection->disconnect()V": {
                HttpURLConnection connection = (HttpURLConnection) dvmObject.getValue();
                connection.disconnect();
                return;
            }
        }

        super.callVoidMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        if ("java/net/HttpURLConnection->getResponseCode()I".equals(signature)) {
            HttpURLConnection connection = (HttpURLConnection) dvmObject.getValue();
            try {
                return connection.getResponseCode();
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        return super.callIntMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        if ("android/content/SharedPreferences$Editor->commit()Z".equals(signature)) {
            return true;
        }

        return super.callBooleanMethod(vm, dvmObject, signature, varArg);
    }
}