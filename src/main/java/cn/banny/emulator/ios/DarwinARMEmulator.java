package cn.banny.emulator.ios;

import cn.banny.emulator.AbstractSyscallHandler;
import cn.banny.emulator.arm.AbstractARMEmulator;
import cn.banny.emulator.memory.Memory;

public class DarwinARMEmulator extends AbstractARMEmulator {

    public DarwinARMEmulator() {
        this(null);
    }

    public DarwinARMEmulator(String processName) {
        super(processName);
    }

    @Override
    protected Memory createMemory(AbstractSyscallHandler syscallHandler) {
        return new MachOLoader(this, syscallHandler);
    }
}
