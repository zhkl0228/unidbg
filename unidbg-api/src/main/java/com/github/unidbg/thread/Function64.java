package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.memory.Memory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;

import java.util.Arrays;

public class Function64 extends MainTask {

    private static final Logger log = LoggerFactory.getLogger(Function64.class);

    private final long address;
    private final boolean paddingArgument;
    private final Number[] arguments;

    public Function64(int pid, long address, long until, boolean paddingArgument, Number... arguments) {
        super(pid, until);
        this.address = address;
        this.paddingArgument = paddingArgument;
        this.arguments = arguments;
    }

    @Override
    protected Number run(AbstractEmulator<?> emulator) {
        Backend backend = emulator.getBackend();
        Memory memory = emulator.getMemory();
        ARM.initArgs(emulator, paddingArgument, arguments);

        long sp = memory.getStackPoint();
        if (sp % 16 != 0) {
            log.info("SP NOT 16 bytes aligned", new Exception(emulator.getStackPointer().toString()));
        }
        backend.reg_write(Arm64Const.UC_ARM64_REG_LR, until);
        return emulator.emulate(address, until);
    }

    @Override
    public String toThreadString() {
        return "Function64 address=0x" + Long.toHexString(address) + ", arguments=" + Arrays.toString(arguments);
    }

}
