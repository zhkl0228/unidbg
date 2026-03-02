package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.HypervisorFactory;
import com.github.unidbg.file.ios.DarwinFileIO;
import com.github.unidbg.hook.HookLoader;
import com.github.unidbg.ios.ipa.SymbolResolver;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.IOException;

public class A12ZTest {

    public static void main(String[] args) throws IOException {
        DarwinEmulatorBuilder builder = DarwinEmulatorBuilder.for64Bit();
        builder.addBackendFactory(new HypervisorFactory(true));
        Emulator<DarwinFileIO> emulator = builder.build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver().setOverride());
        emulator.getSyscallHandler().setVerbose(false);
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        emulator.getMemory().addHookListener(new SymbolResolver(emulator));

        Module module = emulator.loadLibrary(new File("unidbg-ios/src/test/resources/example_binaries/a12z_osx"));
        long start = System.currentTimeMillis();
        emulator.traceRead(0x100004000L, 0x100004000L + 0x8);
        emulator.traceWrite(0x100008194L, 0x100008194L + 8);
        emulator.traceCode(0x100000c80L, 0x100000c80L + 0x100);
        emulator.attach().addBreakPoint(0x10000392cL, (emu, address) -> {
            System.out.println("Hit breakpoint: 0x" + Long.toHexString(address));
            return true;
        });
        HookLoader.load(emulator).hookObjcMsgSend((emulator1, systemClass, className, cmd, lr) -> {
            System.out.printf("onMsgSend [%s %s]%n", className, cmd);
            return false;
        });
        int ret = module.callEntry(emulator);
        System.err.println("testA12Z backend=" + emulator.getBackend() + ", ret=0x" + Integer.toHexString(ret) + ", offset=" + (System.currentTimeMillis() - start) + "ms");
    }

}
