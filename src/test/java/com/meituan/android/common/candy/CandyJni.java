package com.meituan.android.common.candy;

import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.LibraryResolver;
import cn.banny.emulator.Module;
import cn.banny.emulator.arm.ARMEmulator;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.file.IOResolver;
import cn.banny.emulator.hook.hookzz.*;
import cn.banny.emulator.linux.android.AndroidARMEmulator;
import cn.banny.emulator.linux.android.AndroidResolver;
import cn.banny.emulator.linux.android.dvm.*;
import cn.banny.emulator.linux.file.ByteArrayFileIO;
import cn.banny.emulator.linux.file.SimpleFileIO;
import cn.banny.emulator.memory.Memory;
import com.sun.jna.Pointer;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

public class CandyJni extends AbstractJni implements IOResolver {

    private static final String APP_PACKAGE_NAME = "com.sankuai.meituan.takeoutnew";

    private static LibraryResolver createLibraryResolver() {
        return new AndroidResolver(19);
    }

    private static ARMEmulator createARMEmulator() {
        return new AndroidARMEmulator(APP_PACKAGE_NAME);
    }

    private final ARMEmulator emulator;
    private final VM vm;

    private final DvmClass classCandyJni;

    private static final String INSTALL_PATH = "/data/app/com.sankuai.meituan.takeoutnew-1.apk";
    private static final String APK_PATH = "src/test/resources/app/7.8.4.70804.apk";

    private final Module module;

    private CandyJni() throws IOException {
        emulator = createARMEmulator();
        emulator.getSyscallHandler().addIOResolver(this);
        System.out.println("== init ===");

        final Memory memory = emulator.getMemory();
        memory.setLibraryResolver(createLibraryResolver());
        memory.setCallInitFunction();

        vm = emulator.createDalvikVM(new File(APK_PATH));
        DalvikModule dm = vm.loadLibrary("mtguard", false);
        Logger.getLogger("cn.banny.emulator.AbstractEmulator").setLevel(Level.INFO);
        dm.callJNI_OnLoad(emulator);
        module = dm.getModule();

        classCandyJni = vm.resolveClass("com.meituan.android.common.candy.CandyJni".replace(".", "/"));

         memory.runLastThread(TimeUnit.SECONDS.toMicros(5));
    }

    private void destroy() throws IOException {
        emulator.close();
        System.out.println("module=" + module);
        System.out.println("== destroy ===");
    }

    public static void main(String[] args) throws Exception {
        CandyJni test = new CandyJni();
        test.getCandyDataWithKey();
        test.destroy();
    }

    private String getCandyDataWithKey(byte[] data) {
        /*byte[] s1 = DigestUtils.sha1("MtguardHamcKeySANKUAI_SALT".getBytes());
        String salt = "TEST_SALT" + APP_PACKAGE_NAME + Base64.encodeBase64String(DigestUtils.md5(signature));
        byte[] s2 = DigestUtils.sha1(salt.getBytes());
        Inspector.inspect(s1, salt);
        Inspector.inspect(s2, salt);*/

        String str = "Tb6yTwgSEvbLgLtguw21Q80dR8atTLZ9gbOyX3m9FB0FMGWI60SALA==";
//        Inspector.inspect(Base64.decodeBase64(str), str);
        byte[] m1 = new byte[0x40];
        byte[] m2 = new byte[0x40];
        byte[] key = Arrays.copyOf(str.getBytes(), 0x40);
        for (int i = 0; i < key.length; i++) {
            m1[i] = (byte) (key[i] ^ 0x5c);
            m2[i] = (byte) (key[i] ^ 0x36);
        }
        /*Inspector.inspect(m1, "m1");
        Inspector.inspect(m2, "m2");*/
        ByteBuffer buffer = ByteBuffer.allocate(m2.length + data.length);
        buffer.put(m2);
        buffer.put(data);
        byte[] o1 = DigestUtils.sha1(buffer.array());

        buffer = ByteBuffer.allocate(m1.length + o1.length);
        buffer.put(m1);
        buffer.put(o1);
        byte[] o2 = DigestUtils.sha1(buffer.array());

        String result = Base64.encodeBase64String(o2);
        Inspector.inspect(o2, result);
        return result;
    }

    private void getCandyDataWithKey() {
        vm.setJni(this);
        Logger.getLogger("cn.banny.emulator.AbstractEmulator").setLevel(Level.DEBUG);

        byte[] data = "HelloWorld".getBytes();
        String key = "candyKey";

        /*IHookZz hookZz = HookZz.getInstance(emulator);
        hookZz.wrap(module.base + 0x00004FD1, new WrapCallback<Arm32RegisterContext>() {
            @Override
            public void preCall(Emulator emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                Pointer pointer = ctx.getR0Pointer();
                int size = (int) ctx.getR1();
                byte[] data = pointer.getByteArray(0, size);
                Inspector.inspect(data, "data sha1=" + DigestUtils.sha1Hex(data) + ", pointer=" + pointer);
                ctx.set("pointer", ctx.getR2Pointer());
            }
            @Override
            public void postCall(Emulator emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                super.postCall(emulator, ctx, info);

                Pointer pointer = ctx.get("pointer");
                byte[] out = pointer.getByteArray(0, 20);
                Inspector.inspect(out, "sha pointer=" + pointer);
            }
        });*/

        IHookZz hookZz = HookZz.getInstance(emulator);
        hookZz.wrap(module.base + 0x00004BED, new WrapCallback<Arm32RegisterContext>() {
            @Override
            public void preCall(Emulator emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                Pointer pointer = ctx.getR0Pointer();
                int size = (int) ctx.getR1();
                byte[] data = pointer.getByteArray(0, size);
                Inspector.inspect(data, "sign pointer=" + pointer);
                ctx.set("pointer", ctx.getStackPointer().getPointer(0));
            }
            @Override
            public void postCall(Emulator emulator, Arm32RegisterContext ctx, HookEntryInfo info) {
                super.postCall(emulator, ctx, info);

                Pointer pointer = ctx.get("pointer");
                byte[] out = pointer.getByteArray(0, 20);
                Inspector.inspect(out, "sign out=" + pointer);
            }
        });

        DvmObject context = vm.resolveClass("android/content/Context").newObject(null);
        long start = System.currentTimeMillis();
        Number ret = classCandyJni.callStaticJniMethod(emulator, "getCandyDataWithKey(Ljava/lang/Object;[BLjava/lang/String;)Ljava/lang/String;",
                context,
                vm.addLocalObject(new ByteArray(data)),
                vm.addLocalObject(new StringObject(vm, key))
        );
        long hash = ret.intValue() & 0xffffffffL;
        StringObject obj = vm.getObject(hash);
        vm.deleteLocalRefs();
        Inspector.inspect(Base64.decodeBase64(obj.getValue()), "getCandyDataWithKey = " + obj.getValue() + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        start = System.currentTimeMillis();
        ret = classCandyJni.callStaticJniMethod(emulator, "getCandyDataWithKey(Ljava/lang/Object;[BLjava/lang/String;)Ljava/lang/String;",
                context,
                vm.addLocalObject(new ByteArray(data)),
                vm.addLocalObject(new StringObject(vm, "candyKey"))
        );
        hash = ret.intValue() & 0xffffffffL;
        obj = vm.getObject(hash);
        vm.deleteLocalRefs();
        Inspector.inspect(Base64.decodeBase64(obj.getValue()), "getCandyDataWithKey = " + obj.getValue() + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        /*IxHook ixHook = XHookImpl.getInstance(emulator);
        ixHook.register("libmtguard.so", "__aeabi_memcpy", new ReplaceCallback() {
            @Override
            public HookStatus onCall(Emulator emulator, long originFunction) {
                Unicorn unicorn = emulator.getUnicorn();
                Pointer dest = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer src = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                int size = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                if (size > 1) {
                    Inspector.inspect(src.getByteArray(0, size), "__aeabi_memcpy dest=" + dest + ", src=" + src);
                }
                return HookStatus.RET(unicorn, originFunction);
            }
        });
        ixHook.refresh();*/

        for (int i = 0; i < 10; i++) {
            Random random = ThreadLocalRandom.current();
            data = new byte[random.nextInt(0x1000) + 1];
            for (int m = 0; m < data.length; m++) {
                data[m] = (byte) random.nextInt();
            }

            start = System.currentTimeMillis();
            // emulator.traceCode(module.base, module.base + module.size);
            // emulator.traceRead(0xbffff618L, 0xbffff618L + 20);
            // emulator.attach(module.base, module.base + module.size).addBreakPoint(module, 0x00004BEC);
            ret = classCandyJni.callStaticJniMethod(emulator, "getCandyDataWithKey(Ljava/lang/Object;[BLjava/lang/String;)Ljava/lang/String;",
                    context,
                    vm.addLocalObject(new ByteArray(data)),
                    vm.addLocalObject(new StringObject(vm, "candyKey"))
            );
            hash = ret.intValue() & 0xffffffffL;
            obj = vm.getObject(hash);
            vm.deleteLocalRefs();
            Inspector.inspect(Base64.decodeBase64(obj.getValue()), "getCandyDataWithKey = " + obj.getValue() + ", offset=" + (System.currentTimeMillis() - start) + "ms");

            if (getCandyDataWithKey(data).equals(obj.getValue())) {
                System.out.println("Test pass");
            } else {
                System.err.println("Test failed");
            }
        }
    }

    @Override
    public FileIO resolve(File workDir, String pathname, int oflags) {
        if ("/proc/self/cmdline".equals(pathname)) {
            return new ByteArrayFileIO(oflags, pathname, APP_PACKAGE_NAME.getBytes());
        }
        if (INSTALL_PATH.equals(pathname)) {
            return new SimpleFileIO(oflags, new File(APK_PATH), pathname);
        }
        if ("/data/misc/zoneinfo/tzdata".equals(pathname)) {
            return new SimpleFileIO(oflags, new File("src/main/resources/android/sdk19/system/usr/share/zoneinfo/tzdata"), pathname);
        }
        return null;
    }

    @Override
    public DvmObject callObjectMethod(BaseVM vm, DvmObject dvmObject, String signature, String methodName, String args, VarArg varArg) {
        if ("android/content/Context->getPackageCodePath()Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, INSTALL_PATH);
        }

        return super.callObjectMethod(vm, dvmObject, signature, methodName, args, varArg);
    }
}
