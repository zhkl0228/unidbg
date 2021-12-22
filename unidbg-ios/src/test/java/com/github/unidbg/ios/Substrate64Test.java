package com.github.unidbg.ios;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.HookStatus;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookLoader;
import com.github.unidbg.hook.MsgSendCallback;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.hook.hookzz.Dobby;
import com.github.unidbg.hook.hookzz.HookEntryInfo;
import com.github.unidbg.hook.hookzz.IHookZz;
import com.github.unidbg.hook.hookzz.InstrumentCallback;
import com.github.unidbg.ios.ipa.SymbolResolver;
import com.github.unidbg.ios.struct.kernel.ThreadBasicInfo;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.thread.PopContextException;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;

public class Substrate64Test extends EmulatorTest<ARMEmulator<DarwinFileIO>> implements MsgSendCallback {

    @Override
    protected LibraryResolver createLibraryResolver() {
        return new DarwinResolver();
    }

    @Override
    protected ARMEmulator<DarwinFileIO> createARMEmulator() {
        DarwinEmulatorBuilder builder = new DarwinEmulatorBuilder(true) {
            @Override
            public ARMEmulator<DarwinFileIO> build() {
                return new DarwinARM64Emulator(processName, rootDir, backendFactories, envList.toArray(new String[0])) {
                    @Override
                    protected UnixSyscallHandler<DarwinFileIO> createSyscallHandler(SvcMemory svcMemory) {
                        return new ARM64SyscallHandler(svcMemory) {
                            @Override
                            protected int semwait_signal(Emulator<?> emulator) {
                                RegisterContext context = emulator.getContext();
                                long tv_sec = context.getLongArg(4);
                                int tv_nsec = context.getIntArg(5);
                                if (tv_sec == 88 && tv_nsec == 0) {
                                    throw new PopContextException();
                                }
                                return super.semwait_signal(emulator);
                            }
                        };
                    }
                };
            }
        };
        return builder.addEnv("CFFIXED_USER_HOME=/var/mobile")
                .setRootDir(new File("target/rootfs/substrate"))
                .build();
    }

    public void testMS() {
        MachOLoader loader = (MachOLoader) emulator.getMemory();
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
        loader.setObjcRuntime(true);
        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/libsubstrate.dylib"));

        Symbol symbol = module.findSymbolByName("_MSGetImageByName");
        assertNotNull(symbol);

        long start = System.currentTimeMillis();
        Number[] numbers = symbol.call(emulator, "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate");
        long ret = numbers[0].longValue();
        System.err.println("_MSGetImageByName ret=0x" + Long.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        symbol = module.findSymbolByName("_MSFindSymbol");
        assertNotNull(symbol);
        start = System.currentTimeMillis();
        // emulator.traceCode();
        numbers = symbol.call(emulator, UnidbgPointer.pointer(emulator, ret), "_MSGetImageByName");
        ret = numbers[0].longValue();
        System.err.println("_MSFindSymbol ret=0x" + Long.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");

        HookLoader.load(emulator).hookObjcMsgSend(this);

        start = System.currentTimeMillis();

        try {
            byte[] thread_basic_info = Hex.decodeHex("000000008ab502000000000000000000570100000100000001000000000000000000000000000000".toCharArray());
            ThreadBasicInfo basicInfo = new ThreadBasicInfo(thread_basic_info);
            basicInfo.unpack();
            Inspector.inspect(thread_basic_info, basicInfo.toString());
        } catch (DecoderException e) {
            throw new IllegalStateException(e);
        }

        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
        Logger.getLogger(ARM64SyscallHandler.class).setLevel(Level.INFO);
        Logger.getLogger(Dyld64.class).setLevel(Level.INFO);
        loader.getExecutableModule().callEntry(emulator);
        System.err.println("callExecutableEntry offset=" + (System.currentTimeMillis() - start) + "ms");
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getMemory().addHookListener(new SymbolResolver(emulator));
    }

    public static void main(String[] args) throws Exception {
        Substrate64Test test = new Substrate64Test();
        test.setUp();
        test.testMS();
        test.tearDown();
    }

    @Override
    public void onMsgSend(Emulator<?> emulator, boolean systemClass, String className, String cmd, Pointer lr) {
//        System.out.printf("onMsgSend [%s %s] from %s\n", className, cmd, lr);
    }
}
