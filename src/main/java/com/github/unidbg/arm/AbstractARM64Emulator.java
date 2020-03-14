package com.github.unidbg.arm;

import capstone.Capstone;
import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.arm.context.UnicornArm64RegisterContext;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.EventMemHook;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;

public abstract class AbstractARM64Emulator<T extends NewFileIO> extends AbstractEmulator<T> implements ARMEmulator<T> {

    private static final Log log = LogFactory.getLog(AbstractARM64Emulator.class);

    protected final Memory memory;
    private final UnixSyscallHandler<T> syscallHandler;

    private final Capstone capstoneArm64;
    protected static final long LR = 0xffffff80001f0000L;

    private final Dlfcn dlfcn;

    public AbstractARM64Emulator(String processName, File rootDir, String... envs) {
        super(UnicornConst.UC_ARCH_ARM64, UnicornConst.UC_MODE_ARM, processName, 0xffffe0000L, 0x10000, rootDir);

        Cpsr.getArm64(unicorn).switchUserMode();

        unicorn.hook_add_new(new EventMemHook() {
            @Override
            public boolean hook(Unicorn u, long address, int size, long value, Object user) {
                log.warn("memory failed: address=0x" + Long.toHexString(address) + ", size=" + size + ", value=0x" + Long.toHexString(value));
                return false;
            }
        }, UnicornConst.UC_HOOK_MEM_READ_UNMAPPED | UnicornConst.UC_HOOK_MEM_WRITE_UNMAPPED | UnicornConst.UC_HOOK_MEM_FETCH_UNMAPPED, null);

        this.syscallHandler = createSyscallHandler(svcMemory);

        enableVFP();
        this.memory = createMemory(syscallHandler, envs);
        this.dlfcn = createDyld(svcMemory);
        this.memory.addHookListener(dlfcn);

        unicorn.hook_add_new(syscallHandler, this);

        this.capstoneArm64 = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);
        this.capstoneArm64.setDetail(Capstone.CS_OPT_ON);
    }

    @Override
    protected RegisterContext createRegisterContext(Unicorn unicorn) {
        return new UnicornArm64RegisterContext(unicorn, this);
    }

    @Override
    public Dlfcn getDlfcn() {
        return dlfcn;
    }

    @Override
    protected final byte[] assemble(Iterable<String> assembly) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            KeystoneEncoded encoded = keystone.assemble(assembly);
            return encoded.getMachineCode();
        }
    }

    private void enableVFP() {
        long value = ((Number) unicorn.reg_read(Arm64Const.UC_ARM64_REG_CPACR_EL1)).longValue();
        value |= 0x300000; // set the FPEN bits
        unicorn.reg_write(Arm64Const.UC_ARM64_REG_CPACR_EL1, value);
    }

    @Override
    protected Debugger createConsoleDebugger() {
        return new SimpleARM64Debugger(this);
    }

    @Override
    protected void closeInternal() {
        for (FileIO io : syscallHandler.fdMap.values()) {
            io.close();
        }

        capstoneArm64.close();
    }

    @Override
    public Module loadLibrary(File libraryFile) throws IOException {
        return memory.load(libraryFile);
    }

    @Override
    public Module loadLibrary(File libraryFile, boolean forceCallInit) throws IOException {
        return memory.load(libraryFile, forceCallInit);
    }

    @Override
    public Memory getMemory() {
        return memory;
    }

    @Override
    public SyscallHandler<T> getSyscallHandler() {
        return syscallHandler;
    }

    @Override
    public final void showRegs() {
        this.showRegs((int[]) null);
    }

    @Override
    public final void showRegs(int... regs) {
        ARM.showRegs64(this, regs);
    }

    @Override
    public Capstone.CsInsn[] printAssemble(PrintStream out, long address, int size) {
        Capstone.CsInsn[] insns = disassemble(address, size, 0);
        printAssemble(out, insns, address);
        return insns;
    }

    @Override
    public Capstone.CsInsn[] disassemble(long address, int size, long count) {
        byte[] code = unicorn.mem_read(address, size);
        return capstoneArm64.disasm(code, address, count);
    }

    @Override
    public Capstone.CsInsn[] disassemble(long address, byte[] code, boolean thumb, long count) {
        if (thumb) {
            throw new IllegalStateException();
        }
        return capstoneArm64.disasm(code, address, count);
    }

    private void printAssemble(PrintStream out, Capstone.CsInsn[] insns, long address) {
        StringBuilder sb = new StringBuilder();
        for (Capstone.CsInsn ins : insns) {
            sb.append("### Trace Instruction ");
            sb.append(ARM.assembleDetail(this, ins, address, false));
            sb.append('\n');
            address += ins.size;
        }
        out.print(sb.toString());
    }

    @Override
    public int getPointerSize() {
        return 8;
    }

    @Override
    public int getPageAlign() {
        return PAGE_ALIGN;
    }

    @Override
    public Number[] eFunc(long begin, Number... arguments) {
        long spBackup = memory.getStackPoint();
        try {
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
            final Arguments args = ARM.initArgs(this, isPaddingArgument(), arguments);
            return eFunc(begin, args, LR, true);
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    @Override
    public void eInit(long begin, Number... arguments) {
        long spBackup = memory.getStackPoint();
        try {
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
            final Arguments args = ARM.initArgs(this, isPaddingArgument(), arguments);
            eFunc(begin, args, LR, false);
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    @Override
    public Number eEntry(long begin, long sp) {
        long spBackup = memory.getStackPoint();
        try {
            memory.setStackPoint(sp);
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
            return emulate(begin, LR, timeout, true);
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    @Override
    public Unicorn eBlock(long begin, long until) {
        long spBackup = memory.getStackPoint();
        try {
            unicorn.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
            emulate(begin, until, traceInstruction ? 0 : timeout, true);
            return unicorn;
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    @Override
    protected Pointer getStackPointer() {
        return UnicornPointer.register(this, Arm64Const.UC_ARM64_REG_SP);
    }
}
