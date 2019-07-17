package com.ces;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.debugger.Debugger;
import cn.banny.unidbg.debugger.DebuggerType;
import cn.banny.unidbg.file.FileIO;
import cn.banny.unidbg.file.IOResolver;
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
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * @program: unidbg
 * @description: douyin's libcms.so
 * @author: space
 * @create: 2019-07-11 14:31
 */
public class CMS extends AbstractJni implements IOResolver {


    private static final org.slf4j.Logger logger = LoggerFactory.getLogger("spaceinfo");

    private static final String APP_PACKAGE_NAME = "com.ss.android.ugc.aweme";
    private static final String APK_PATH = "src/test/resources/app/base.apk";
    private static final String INSTALL_PATH = "/data/app/com.ss.android.ugc.aweme-1/base.apk";


    private final ARMEmulator emulator;
    private final VM vm;
    private final DvmClass cmsDVM;
    private final DvmClass userinfoDVM;
//    private final DvmClass tongdunDVM;

    private final Module module;


    public CMS() throws IOException {




        emulator = new AndroidARMEmulator(APP_PACKAGE_NAME);
        emulator.getSyscallHandler().addIOResolver(this);

        System.out.println("------- init libcms.so -------");

        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(new File(APK_PATH));
        vm.setJni(this);
        DalvikModule dm = vm.loadLibrary("cms", false);


        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();

        cmsDVM = vm.resolveClass("com/ss/sys/ces/a");
        userinfoDVM = vm.resolveClass("com/ss/android/common/applog/UserInfo");
//        tongdunDVM = vm.resolveClass("com/ss/sys/secuni/b/c");
    }

    private void destroy() throws IOException {
        emulator.close();;
        System.out.println("module = " + module);
        System.out.println("------- libcms.so destory -------");
    }

    public static void main(String[] args) throws Exception{
        CMS cms = new CMS();

        cms.sign();


        cms.destroy();
    }




    /**
     * 签名检验
     */
    private void sign() {
        Logger.getLogger("cn.banny.unidbg.AbstractEmulator").setLevel(Level.DEBUG);
        Logger.getLogger("cn.banny.unidbg.linux.android.dvm").setLevel(Level.DEBUG);
        Logger.getLogger("cn.banny.unidbg.file").setLevel(Level.DEBUG);
        Logger.getLogger("cn.banny.unidbg.linux.ARMSyscallHandler").setLevel(Level.DEBUG);
        userinfoDVM.callStaticJniMethod(emulator, "setAppId(I)V", 1128);
        Number i = userinfoDVM.callStaticJniMethod(emulator, "initUser(Ljava/lang/String;)I", vm.addLocalObject(new StringObject(vm, "a3668f0afac72ca3f6c1697d29e0e1bb1fef4ab0285319b95ac39fa42c38d05f")));
        System.out.println("initUser ret: " + i.intValue());


        // 0x4002a65c
        // 0x40016d61
//        Debugger attach = emulator.attach(DebuggerType.GDB_SERVER);
//        emulator.traceRead();
        Debugger attach = emulator.attach(DebuggerType.SIMPLE);
//        emulator.attach(module.base, module.base + module.size).addBreakPoint(module, 0x1a8a4);


        Object custom = null;
        DvmObject context = vm.resolveClass("android/content/Context").newObject(custom);
        Number ret = cmsDVM.callStaticJniMethod(this.emulator, "rb(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)[B",
                vm.addLocalObject(context),
                vm.addLocalObject(new StringObject(vm, "Login")),
                vm.addLocalObject(new StringObject(vm, "")));


//        Number ret = cmsDVM.callStaticJniMethod(emulator, "e([B)[B", vm.addLocalObject(new ByteArray("888888888".getBytes())));



        long hash = ret.intValue() & 0xffffffffL;
        ByteArray array = vm.getObject(hash);
        Inspector.inspect(array.getValue(), "n0 ret=" + ret + ", offset=" + (System.currentTimeMillis()) + "ms");



//        System.out.println("split ---------------");
//        Number ret1 = cmsDVM.callStaticJniMethod(emulator, "d([B)[B", vm.addLocalObject(array));
//        long hash1 = ret1.intValue() & 0xffffffffL;
//        ByteArray array1 = vm.getObject(hash1);
//        Inspector.inspect(array1.getValue(), "n0 ret=" + ret + ", offset=" + (System.currentTimeMillis()) + "ms");



        vm.deleteLocalRefs();

    }


    @Override
    public FileIO resolve(File workDir, String pathname, int oflags) {
        logger.info("----- resolve, pathname = [{}]-----" , pathname);

        if ("/data/app/com.ss.android.ugc.aweme-1/base.apk".equals(pathname)) {
            return new SimpleFileIO(oflags, new File("src/test/resources/app/base.apk"), pathname);
        }

        if ("/proc/self/maps".equals(pathname)) {
            return new SimpleFileIO(oflags, new File("src/test/resources/files/maps"), pathname);
        }

        if ("/proc/self/cmdline".equals(pathname)) {
            return new SimpleFileIO(oflags, new File("src/test/resources/files/cmdline"), pathname);
        }

        if ("/sys/class/net/wlan0/address".equals(pathname)) {
            return new SimpleFileIO(oflags, new File("src/test/resources/files/address"), pathname);
        }

        if ("/proc/self/status".equals(pathname)) {
            return new ByteArrayFileIO(oflags, pathname, "TracerPid:\t0\n".getBytes());
        }


        return null;
    }


    @Override
    public DvmObject getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        System.out.println(signature);

        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        logger.info("----- getStaticIntField -----, signature", signature);
        switch (signature) {
            case "java/util/zip/ZipFile->OPEN_READ:I":
                return 1;
        }

        return super.getStaticIntField(vm, dvmClass, signature);
    }

    @Override
    public DvmObject getObjectField(BaseVM vm, DvmObject dvmObject, String signature) {
        logger.info("----- getObjectField ----- , signature = [{}]", signature);
        switch (signature) {
            case "android/content/pm/ApplicationInfo->sourceDir:Ljava/lang/String;" :
                return new StringObject(vm, INSTALL_PATH);

        }
        return super.getObjectField(vm, dvmObject, signature);
    }



    @Override
    public boolean callStaticBooleanMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        System.out.println(signature);

        return super.callStaticBooleanMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public boolean callStaticBooleanMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        logger.info("----- callStaticBooleanMethodV ----- , signature = [{}]", signature);
        if ("android/os/Debug->isDebuggerConnected()Z".equals(signature)) {
            return false;
        }

        return super.callStaticBooleanMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public int callStaticIntMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        System.out.println(signature);

        return super.callStaticIntMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public int callStaticIntMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        System.out.println(signature);

        return super.callStaticIntMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public DvmObject callObjectMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
//        if (signature.contains("getBytes") || signature.contains("ZipEntry->getName")|| signature.contains("getNextEntry")) {
//        } else {
            logger.info("----- callObjectMethodV ----- , 签名 = [{}]", signature);
//        }
        switch (signature) {
            case "android/content/pm/ApplicationInfo;->getApplicationInfo()Landroid/content/pm/ApplicationInfo;":
                return vm.resolveClass("android/content/pm/ApplicationInfo").newObject(null);

            case "android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;" :
                StringObject serviceName = vaList.getObject(0);
                logger.info("----- android/content/Context->getSystemService name= [{}]", serviceName);
                return new SystemService(vm, serviceName.getValue());
            case "android/net/wifi/WifiManager->getConnectionInfo()Landroid/net/wifi/WifiInfo;":
                return vm.resolveClass("Landroid/net/wifi/WifiInfo").newObject(null);
            case "Landroid/net/wifi/WifiInfo->getSSID()Ljava/lang/String;":
                return new StringObject(vm, "Searching");
            case "Landroid/net/wifi/WifiInfo->getBSSID()Ljava/lang/String;":
                return new StringObject(vm, "00:81:dc:08:db:69");
            case "java/lang/String->getBytes(Ljava/lang/String;)[B":
                String str = ((StringObject) dvmObject).getValue();
//                logger.info("----- java/lang/String->getBytes(Ljava/lang/String;)[B ----- , dvmObj = [{}], ",str);
                return new ByteArray(str.getBytes());
            case "android/content/Context->getContentResolver()Landroid/content/ContentResolver;":
                return vm.resolveClass("android/content/ContentResolver").newObject(null);
            case "android/content/ContentResolver->call(Landroid/net/Uri;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)Landroid/os/Bundle;":
                return vm.resolveClass("android/os/Bundle").newObject(null);
            case "android/os/Bundle->getString(Ljava/lang/String;)Ljava/lang/String;":
                StringObject obj = vaList.getObject(0);
                logger.info("----- android/os/Bundle->getString(Ljava/lang/String;)Ljava/lang/String; ----- params = [{}]", obj);
                return new StringObject(vm, "112233448855");

            case "java/net/NetworkInterface->getHardwareAddress()[B" :
                ByteArrayOutputStream baos = (ByteArrayOutputStream) dvmObject.getValue();

                String addr = "11:22:33:44:55:66";
//                String addr = "";
                byte[] bytes = addr.getBytes();
                // Inspector.inspect(data, "java/io/ByteArrayOutputStream->toByteArray()");
                return new ByteArray(bytes);
            case "java/util/zip/ZipInputStream->getNextEntry()Ljava/util/zip/ZipEntry;":
//                logger.info("----- java/util/zip/ZipInputStream->getNextEntry()Ljava/util/zip/ZipEntry;-----, dvmobj = [{}]", dvmObject);
                ZipInputStream zipInputStream = (ZipInputStream) dvmObject.getValue();
                try {
                    ZipEntry nextEntry = zipInputStream.getNextEntry();
                    return vm.resolveClass("java/util/zip/ZipEntry").newObject(nextEntry);

                } catch (IOException e) {
                    e.printStackTrace();
                }
                return vm.resolveClass("java/util/zip/ZipEntry").newObject(null);

            case "java/util/zip/ZipEntry->getName()Ljava/lang/String;":
//                logger.info("----- java/util/zip/ZipEntry->getName()Ljava/lang/String; -----, dvmobj = [{}]", dvmObject);


                ZipEntry ze = (ZipEntry) dvmObject.getValue();
//                logger.info("----- java/util/zip/ZipEntry->getName()Ljava/lang/String; -----, getName = [{}]", ze.getName());
                return new StringObject(vm, ze.getName());

            case "java/util/zip/ZipFile->getEntry(Ljava/lang/String;)Ljava/util/zip/ZipEntry;":
                ZipFile zipFile = (ZipFile) dvmObject.getValue();
                StringObject stringObject = vaList.getObject(0);
                logger.info("----- java/util/zip/ZipFile->getEntry(Ljava/lang/String;)Ljava/util/zip/ZipEntry; -----, params = [{}]", stringObject);
                return vm.resolveClass("java/util/zip/ZipEntry").newObject(zipFile.getEntry(stringObject.getValue()));

        }

        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {

        System.out.println(signature);


        return super.callStaticObjectMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        logger.info("----- callStaticObjectMethodV ----- , 签名 = [{}]", signature);


        switch (signature) {
            case "com/ss/sys/ces/a->njss(ILjava/lang/Object;)Ljava/lang/Object;":
                int i1= vaList.getInt(0);
                Object object = vaList.getObject(4);
                logger.info("----- 调用 njss 函数, param 1 = [{}], param 2 = [{}]", i1, object);
                if (i1 == 121) {
                    return new StringObject(vm, "");
                } else if (i1 == 111) {
                    return new StringObject(vm, "[]");
                } else if (i1 == 114){
                    return new StringObject(vm, "");
                }else if (i1 == 112){
                    return new StringObject(vm, "99000972672669");
                }else if (i1 == 113){
                    return new StringObject(vm, "460110436466359");
                } else if (i1 == 119) {
                    return new StringObject(vm, "GMT+08:00");
                } else if (i1 == 118) {
                    return new StringObject(vm, "zh_CN");
                }
                break;

            case "android/app/ActivityThread->currentApplication()Landroid/app/Application;":
                return vm.resolveClass("android/content/pm/ApplicationInfo;").newObject(null);

            case "android/provider/Settings$Secure->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;" :
                 StringObject params = vaList.getObject(4);
                 // android_id
                logger.info("----- android/provider/Settings$Secure->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String; params= [{}]", params);
                return new StringObject(vm , "8888888888888888");

            case "android/net/Uri->parse(Ljava/lang/String;)Landroid/net/Uri;" :
                params = vaList.getObject(4);
                logger.info("----- android/net/Uri->parse(Ljava/lang/String;)Landroid/net/Uri; ----- params = [{}]", params);
                return vm.resolveClass("android/net/Uri").newObject(null);
            case "java/net/NetworkInterface->getByName(Ljava/lang/String;)Ljava/net/NetworkInterface;" :
                params = vaList.getObject(0);
                logger.info("----- java/net/NetworkInterface->getByName(Ljava/lang/String;)Ljava/net/NetworkInterface; ----- params = [{}]", params);
                return vm.resolveClass("java/net/NetworkInterface").newObject(null);
        }

        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
        logger.info("----- callIntMethodV -----, signature = [{}]", signature);
        switch (signature) {
            case "Landroid/net/wifi/WifiInfo->getIpAddress()I":
                return 1226811584;

        }

        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }


    @Override
    public long callLongMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
        logger.info("----- callLongMethodV -----, signature = [{}]", signature);


        return super.callLongMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public long callStaticLongMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        System.out.println(signature);

        return super.callStaticLongMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public boolean callBooleanMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        System.out.println(signature);

        return super.callBooleanMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
        System.out.println(signature);

        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject dvmObject, String signature) {
        System.out.println(signature);

        return super.getIntField(vm, dvmObject, signature);
    }

    @Override
    public long getLongField(BaseVM vm, DvmObject dvmObject, String signature) {
        System.out.println(signature);

        return super.getLongField(vm, dvmObject, signature);
    }

    @Override
    public void callStaticVoidMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        System.out.println(signature);

        super.callStaticVoidMethod(vm, dvmClass, signature, varArg);
    }

    @Override
    public void callStaticVoidMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        System.out.println(signature);

        super.callStaticVoidMethodV(vm, dvmClass, signature, vaList);
    }

    @Override
    public void setObjectField(BaseVM vm, DvmObject dvmObject, String signature, DvmObject value) {
        System.out.println(signature);

        super.setObjectField(vm, dvmObject, signature, value);
    }

    @Override
    public boolean getBooleanField(BaseVM vm, DvmObject dvmObject, String signature) {
        System.out.println(signature);

        return super.getBooleanField(vm, dvmObject, signature);
    }

    @Override
    public DvmObject newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        System.out.println(signature);

        return super.newObject(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject newObjectV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        logger.info("----- newObjectV -----, signature = [{}]", signature);
        switch (signature) {
            case "java/io/FileInputStream-><init>(Ljava/lang/String;)V" :
                DvmObject stringObject = vaList.getObject(0);
                logger.info("----- java/io/FileInputStream-><init>(Ljava/lang/String;) -----, params = [{}]", stringObject);
                try {
                    return dvmClass.newObject(new FileInputStream(APK_PATH));
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                }

            case "java/io/BufferedInputStream-><init>(Ljava/io/InputStream;)V":
                DvmObject obj = vaList.getObject(0);
                InputStream inputStream = (InputStream) obj.getValue();
                return dvmClass.newObject(new BufferedInputStream(inputStream));
            case "java/util/zip/ZipInputStream-><init>(Ljava/io/InputStream;)V":
                obj = vaList.getObject(0);
                inputStream = (InputStream) obj.getValue();
                return dvmClass.newObject(new ZipInputStream(inputStream));

            case "java/io/File-><init>(Ljava/lang/String;)V":
                obj = vaList.getObject(0);
                logger.info("----- java/io/File-><init>(Ljava/lang/String;)V -----, params = [{}]", obj);
                return dvmClass.newObject(obj.getValue());

            case "java/util/zip/ZipFile-><init>(Ljava/io/File;I)V":
                obj = vaList.getObject(0);
                int obj2 = vaList.getInt(4);
                logger.info("----- java/util/zip/ZipFile-><init>(Ljava/io/File;I)V -----, param1 = [{}], param2 = [{}]", obj, obj2);
//                File iofile = new File(APK_PATH);
                File iofile = new File(APK_PATH);
                try {
                    return dvmClass.newObject(new ZipFile(iofile,  obj2>>32));
                } catch (IOException e) {
                    e.printStackTrace();
                }
                return dvmClass.newObject(null);

        }


        return super.newObjectV(vm, dvmClass, signature, vaList);
    }

    @Override
    public void setIntField(BaseVM vm, DvmObject dvmObject, String signature, int value) {
        System.out.println(signature);

        super.setIntField(vm, dvmObject, signature, value);
    }

    @Override
    public void setLongField(BaseVM vm, DvmObject dvmObject, String signature, long value) {
        System.out.println(signature);

        super.setLongField(vm, dvmObject, signature, value);
    }

    @Override
    public void setBooleanField(BaseVM vm, DvmObject dvmObject, String signature, boolean value) {
        System.out.println(signature);

        super.setBooleanField(vm, dvmObject, signature, value);
    }

    @Override
    public void setDoubleField(BaseVM vm, DvmObject dvmObject, String signature, double value) {
        System.out.println(signature);

        super.setDoubleField(vm, dvmObject, signature, value);
    }

    @Override
    public DvmObject callObjectMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        System.out.println(signature);

        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        System.out.println(signature);

        return super.callIntMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject dvmObject, String signature, VarArg varArg) {
        System.out.println(signature);

        super.callVoidMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject dvmObject, String signature, VaList vaList) {
        logger.info("----- callVoidMethodV -----, signature = [{}]", signature);
        switch (signature) {
            case "java/util/zip/ZipInputStream->close()V":
                ZipInputStream zipInputStream = (ZipInputStream) dvmObject.getValue();
                try {
                    zipInputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                return;
        }


    }

    @Override
    public void setStaticLongField(BaseVM vm, String signature, long value) {
        System.out.println(signature);

        super.setStaticLongField(vm, signature, value);
    }

    @Override
    public long getStaticLongField(BaseVM vm, String signature) {
        System.out.println(signature);

        return super.getStaticLongField(vm, signature);
    }


}
