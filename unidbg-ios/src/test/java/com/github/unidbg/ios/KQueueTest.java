package com.github.unidbg.ios;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.memory.Memory;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;

public class KQueueTest {

    private final Emulator<?> emulator;
    private final Module module;

    public KQueueTest() {
        this.emulator = DarwinEmulatorBuilder.for32Bit()
                .setRootDir(new File("target/rootfs/kqueue"))
                .addBackendFactory(new DynarmicFactory(true))
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());
        this.module = memory.load(new File("unidbg-ios/src/test/resources/example_binaries/kqueue"));
    }

    private void test() {
        long start = System.currentTimeMillis();
        module.callEntry(emulator);
        System.out.println("offset=" + (System.currentTimeMillis() - start) + "ms, backend=" + emulator.getBackend());
    }

    private void destroy() {
        IOUtils.close(emulator);
    }

    public static void main(String[] args) {
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.INFO);
        Logger.getLogger(ARM32SyscallHandler.class).setLevel(Level.INFO);
        Logger.getLogger(DarwinSyscallHandler.class).setLevel(Level.INFO);
        Logger.getLogger("com.github.unidbg.thread").setLevel(Level.INFO);
        Logger.getLogger("com.github.unidbg.ios.kevent").setLevel(Level.INFO);
        KQueueTest test = new KQueueTest();
        test.test();
        test.destroy();
    }

}
