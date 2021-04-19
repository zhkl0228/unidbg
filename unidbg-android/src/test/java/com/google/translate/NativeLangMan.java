package com.google.translate;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.KvmFactory;
import com.github.unidbg.debugger.DebugRunnable;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.google.protobuf.InvalidProtocolBufferException;
import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;

import java.io.File;

public class NativeLangMan extends TestCase implements IOResolver<AndroidFileIO> {

    private static final String model_path = "/data/user/files";

    private static final String zh = "zh-Hans"; //中文
    private static final String en = "en"; //英文

    private final AndroidEmulator emulator;
    private final VM vm;
    private final DvmClass cNativeLangMan;

    private AndroidEmulator createARMEmulator() {
        return AndroidEmulatorBuilder
                .for32Bit()
                .addBackendFactory(new KvmFactory(true))
                .addBackendFactory(new DynarmicFactory(true))
                .setProcessName("com.google.translate")
                .build();
    }

    public NativeLangMan(){
        emulator = createARMEmulator(); // 创建模拟器实例，要模拟32位或者64位，在这里区分
        emulator.getSyscallHandler().addIOResolver(this);

        final Memory memory = emulator.getMemory(); // 模拟器的内存操作接口
        memory.setLibraryResolver(new AndroidResolver(23));// 设置系统类库解析
        vm = emulator.createDalvikVM(null); // 创建Android虚拟机
        vm.setVerbose(true);// 设置是否打印Jni调用细节
        new AndroidModule(emulator, vm).register(memory);

        // 自行修改文件路径,loadLibrary是java加载so的方法
        File file = new File("unidbg-android/src/test/resources/example_binaries/armeabi-v7a/libtranslate.so");
        DalvikModule dm = vm.loadLibrary(file.exists() ? file : new File("src/test/resources/example_binaries/armeabi-v7a/libtranslate.so"), true);
        dm.callJNI_OnLoad(emulator);// 手动执行JNI_OnLoad函数

        cNativeLangMan = vm.resolveClass("com/google/android/libraries/wordlens/NativeLangMan");

        DvmClass cWordLensSystem = vm.resolveClass("com/google/android/libraries/wordlens/WordLensSystem");

        //检查cpu
        boolean ret = cWordLensSystem.callStaticJniMethodBoolean(emulator, "CheckCPUHasNeonNative()Z");
        System.out.println("CheckCPUHasNeonNative: " + ret + ", backend=" + emulator.getBackend());

        //卸载模型
        int unload = cNativeLangMan.callStaticJniMethodInt(emulator, "unloadDictionaryNative()I");
        System.out.println("unloadDictionaryNative: " + unload);


        //加载模型
        byte[] jkl = createJkl(zh, en);
        int load = cNativeLangMan.callStaticJniMethodInt(emulator, "loadDictionaryNative([B)I", new ByteArray(vm, jkl));

        System.out.println("loadDictionaryNative: " + load);
        if (load != 0) {
            throw new IllegalStateException();
        }
    }

    private void transTest(){
        //输入文字
        doTrans("你吃了吗");
        doTrans("你今天去哪里旅行？");

        try {
            System.out.println("执行命令 \"run 中文\" 翻译，例如：run 今天天气怎样？");

            emulator.attach().run(new DebugRunnable<Void>() {
                @Override
                public Void runWithArgs(String[] args) {
                    if (args != null && args.length > 0) {
                        String text = args[0].trim();
                        if (text.length() > 0) {
                            doTrans(text);
                        }
                    }
                    return null;
                }
            });
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void doTrans(String zh) {
        byte[] doTrans = createJkn(zh);
        System.out.println("doTrans " + Hex.encodeHexString(doTrans));
        long startTime = System.currentTimeMillis();
        ByteArray dvmObject = cNativeLangMan.callStaticJniMethodObject(emulator, "doTranslateNative([B)[B", new ByteArray(vm, doTrans));
        System.out.println("doTranslateNative: " + Hex.encodeHexString(dvmObject.getValue()));
        System.out.println("计算用时： "+(System.currentTimeMillis()-startTime)+"ms");
        trans(zh, dvmObject);
    }

    public void trans(String text, ByteArray dvmObject) {
        try {
            com.github.unidbg.android.pb.jkq jkq = com.github.unidbg.android.pb.jkq.parseFrom(dvmObject.getValue());
            System.out.println("doTranslateNative " + text + " => " + jkq.getTranslation() + "\n");
        } catch (InvalidProtocolBufferException e) {
            throw new IllegalStateException(e);
        }
    }


    @Override
    public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
        if (("/proc/" + emulator.getPid() + "/stat").equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, (emulator.getPid() + " (a.out) R 6723 6873 6723 34819 6873 8388608 77 0 0 0 41958 31 0 0 25 0 3 0 5882654 1409024 56 4294967295 134512640 134513720 3215579040 0 2097798 0 0 0 0 0 0 0 17 0 0 0\n").getBytes()));
        }
        if (("/proc/" + emulator.getPid() + "/wchan").equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, "sys_epoll".getBytes()));
        }
        if ("/proc/self/status".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, ("Name:\tsh\n" +
                    "State:\tR (running)\n" +
                    "Tgid:\t5848\n" +
                    "Pid:\t5848\n" +
                    "PPid:\t626\n" +
                    "TracerPid:\t0\n" +
                    "Uid:\t2000\t2000\t2000\t2000\n" +
                    "Gid:\t2000\t2000\t2000\t2000\n" +
                    "Ngid:\t0\n" +
                    "FDSize:\t64\n" +
                    "Groups:\t1004 1007 1011 1015 1028 3001 3002 3003 3006 3009\n" +
                    "VmPeak:\t    7876 kB\n" +
                    "VmSize:\t    7852 kB\n" +
                    "VmLck:\t       0 kB\n" +
                    "VmPin:\t       0 kB\n" +
                    "VmHWM:\t    1524 kB\n" +
                    "VmRSS:\t    1524 kB\n" +
                    "VmData:\t    4300 kB\n" +
                    "VmStk:\t     136 kB\n" +
                    "VmExe:\t     272 kB\n" +
                    "VmLib:\t    2632 kB\n" +
                    "VmPTE:\t      32 kB\n" +
                    "VmSwap:\t       0 kB\n" +
                    "Threads:\t1\n" +
                    "SigQ:\t0/14024\n" +
                    "SigPnd:\t0000000000000000\n" +
                    "ShdPnd:\t0000000000000000\n" +
                    "SigBlk:\t0000000000000000\n" +
                    "SigIgn:\t0000000000001000\n" +
                    "SigCgt:\t000000000801e4ff\n" +
                    "CapInh:\t0000000000000000\n" +
                    "CapPrm:\t0000000000000000\n" +
                    "CapEff:\t0000000000000000\n" +
                    "CapBnd:\t0000003fffffffff\n" +
                    "Seccomp:\t0\n" +
                    "Cpus_allowed:\tf\n" +
                    "Cpus_allowed_list:\t0-3\n" +
                    "Mems_allowed:\t1\n" +
                    "Mems_allowed_list:\t0\n" +
                    "voluntary_ctxt_switches:\t0\n" +
                    "nonvoluntary_ctxt_switches:\t2\n").getBytes()));
        }

        if ("/data/user/files/dict.en_zh_25/merged_dict_en_zh_25_both.bin".equals(pathname)) {
            File file = new File("unidbg-android/src/test/resources/merged_dict_en_zh_25_both.bin");
            return FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, file.exists() ? file : new File("src/test/resources/merged_dict_en_zh_25_both.bin"), pathname));
        }
        if ("/data/user/files/dict.en_zh_25/merged_dict_en_zh_25_from_zh.bin".equals(pathname)) {
            File file = new File("unidbg-android/src/test/resources/merged_dict_en_zh_25_from_zh.bin");
            return FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, file.exists() ? file : new File("src/test/resources/merged_dict_en_zh_25_from_zh.bin"), pathname));
        }
        if ("/data/user/files/dict.en_zh_25/merged_dict_en_zh_25_update.bin".equals(pathname)) {
            File file = new File("unidbg-android/src/test/resources/merged_dict_en_zh_25_update.bin");
            return FileResult.<AndroidFileIO>success(new SimpleFileIO(oflags, file.exists() ? file : new File("src/test/resources/merged_dict_en_zh_25_update.bin"), pathname));
        }
        if ("/proc/cpuinfo".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, ("Processor\t: AArch64 Processor rev 1 (aarch64)\n" +
                    "processor\t: 0\n" +
                    "min_vddcx\t: 400000\n" +
                    "min_vddmx\t: 490000\n" +
                    "BogoMIPS\t: 38.00\n" +
                    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32\n" +
                    "CPU implementer\t: 0x51\n" +
                    "CPU architecture: 8\n" +
                    "CPU variant\t: 0x2\n" +
                    "CPU part\t: 0x201\n" +
                    "CPU revision\t: 1\n" +
                    "\n" +
                    "processor\t: 1\n" +
                    "min_vddcx\t: 400000\n" +
                    "min_vddmx\t: 490000\n" +
                    "BogoMIPS\t: 38.00\n" +
                    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32\n" +
                    "CPU implementer\t: 0x51\n" +
                    "CPU architecture: 8\n" +
                    "CPU variant\t: 0x2\n" +
                    "CPU part\t: 0x201\n" +
                    "CPU revision\t: 1\n" +
                    "\n" +
                    "processor\t: 2\n" +
                    "min_vddcx\t: 400000\n" +
                    "min_vddmx\t: 490000\n" +
                    "BogoMIPS\t: 38.00\n" +
                    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32\n" +
                    "CPU implementer\t: 0x51\n" +
                    "CPU architecture: 8\n" +
                    "CPU variant\t: 0x2\n" +
                    "CPU part\t: 0x205\n" +
                    "CPU revision\t: 1\n" +
                    "\n" +
                    "processor\t: 3\n" +
                    "min_vddcx\t: 400000\n" +
                    "min_vddmx\t: 490000\n" +
                    "BogoMIPS\t: 38.00\n" +
                    "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32\n" +
                    "CPU implementer\t: 0x51\n" +
                    "CPU architecture: 8\n" +
                    "CPU variant\t: 0x2\n" +
                    "CPU part\t: 0x205\n" +
                    "CPU revision\t: 1\n" +
                    "\n" +
                    "CPU param\t: 277 442 442 639 974 296 440 440 613 1101\n" +
                    "Hardware\t: Qualcomm Technologies, Inc MSM8996pro\n").getBytes()));
        }
        if ("/sys/devices/system/cpu/present".equals(pathname) ||
                "/sys/devices/system/cpu/possible".equals(pathname)) {
            return FileResult.<AndroidFileIO>success(new ByteArrayFileIO(oflags, pathname, ("0-3\n".getBytes())));
        }
        return null;
    }


    private byte[] createJkn(String text) {
        com.github.unidbg.android.pb.jkn.Builder jkn = com.github.unidbg.android.pb.jkn.newBuilder();
        jkn.setText(text);
        jkn.setC(false);
        jkn.setD(true);
        jkn.setE(true);
        jkn.setF(false);
        return jkn.build().toByteArray();
    }

    private byte[] createJkl(String from, String to) {
        String tmp = from.equals(en) ? to : from;
        if (tmp.equals(zh)) {
            tmp = "zh";
        }

        com.github.unidbg.android.pb.jkl.Builder jkl = com.github.unidbg.android.pb.jkl.newBuilder();
        jkl.setFrom(from);
        jkl.setTo(to);
        jkl.setD("25");
        jkl.setDictPath(model_path + "/dict.en_" + tmp + "_25");
        jkl.setDictDir(model_path);
        return jkl.build().toByteArray();
    }

    public void testTranslate() {
        doTrans("你吃了吗");
        doTrans("你今天去哪里旅行？");
    }

    public static void main(String[] args) {
        final NativeLangMan translate = new NativeLangMan();
        translate.transTest();
    }
}
