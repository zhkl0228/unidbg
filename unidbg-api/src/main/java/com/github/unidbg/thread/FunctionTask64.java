package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.memory.Memory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;

import java.util.Arrays;

public class FunctionTask64 extends MainTask {

    private static final Log log = LogFactory.getLog(FunctionTask64.class);

    private final boolean paddingArgument;
    private final Number[] arguments;

    public FunctionTask64(long begin, long until, boolean paddingArgument, Number[] arguments) {
        super(begin, until);
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
        return emulator.emulate(begin, until);
    }

    @Override
    public String toString() {
        return super.toString() + ", arguments=" + Arrays.toString(arguments);
    }

}
