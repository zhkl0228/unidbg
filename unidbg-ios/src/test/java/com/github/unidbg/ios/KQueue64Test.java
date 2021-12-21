package com.github.unidbg.ios;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.memory.Memory;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import java.io.File;

public class KQueue64Test {

    private final Emulator<?> emulator;
    private final Module module;

    public KQueue64Test() {
        this.emulator = DarwinEmulatorBuilder.for64Bit()
                .setRootDir(new File("target/rootfs/kqueue"))
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new DarwinResolver());
        this.module = memory.load(new File("unidbg-ios/src/test/resources/example_binaries/kqueue"));
    }

    private void test() {
        module.callEntry(emulator);
    }

    private void destroy() {
        IOUtils.close(emulator);
    }

    public static void main(String[] args) {
        Logger.getLogger(AbstractEmulator.class).setLevel(Level.DEBUG);
        Logger.getLogger(ARM32SyscallHandler.class).setLevel(Level.DEBUG);
        Logger.getLogger(DarwinSyscallHandler.class).setLevel(Level.DEBUG);
        Logger.getLogger("com.github.unidbg.thread").setLevel(Level.DEBUG);
        KQueue64Test test = new KQueue64Test();
        test.test();
        test.destroy();
    }

}
