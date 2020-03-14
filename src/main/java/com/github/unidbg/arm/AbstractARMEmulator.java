package com.github.unidbg.arm;

import capstone.Capstone;
import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.arm.context.UnicornArm32RegisterContext;
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
import unicorn.ArmConst;
import unicorn.EventMemHook;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;

public abstract class AbstractARMEmulator<T extends NewFileIO> extends AbstractEmulator<T> implements ARMEmulator<T> {

    private static final Log log = LogFactory.getLog(AbstractARMEmulator.class);

    public static final long LR = 0xffff0000L;

    protected final Memory memory;
    private final UnixSyscallHandler<T> syscallHandler;

    private final Capstone capstoneArm, capstoneThumb;

    private final Dlfcn dlfcn;

    public AbstractARMEmulator(String processName, File rootDir, String... envs) {
        super(UnicornConst.UC_ARCH_ARM, UnicornConst.UC_MODE_ARM, processName, 0xfffe0000L, 0x10000, rootDir);

        Cpsr.getArm(unicorn).switchUserMode();

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

        this.capstoneArm = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_ARM);
        this.capstoneArm.setDetail(Capstone.CS_OPT_ON);
        this.capstoneThumb = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB);
        this.capstoneThumb.setDetail(Capstone.CS_OPT_ON);

        setupTraps();
    }

    @Override
    protected RegisterContext createRegisterContext(Unicorn unicorn) {
        return new UnicornArm32RegisterContext(unicorn, this);
    }

    @Override
    public Dlfcn getDlfcn() {
        return dlfcn;
    }

    protected void setupTraps() {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
            unicorn.mem_map(LR, 0x10000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
            KeystoneEncoded encoded = keystone.assemble("mov pc, #0");
            byte[] b0 = encoded.getMachineCode();
            ByteBuffer buffer = ByteBuffer.allocate(0x10000);
            // write "mov pc, #0" to all kernel trap addresses so they will throw exception
            for (int i = 0; i < 0x10000; i += 4) {
                buffer.put(b0);
            }
            unicorn.mem_write(LR, buffer.array());
        }
    }

    @Override
    protected final byte[] assemble(Iterable<String> assembly) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
            KeystoneEncoded encoded = keystone.assemble(assembly);
            return encoded.getMachineCode();
        }
    }

    private void enableVFP() {
        int value = ((Number) unicorn.reg_read(ArmConst.UC_ARM_REG_C1_C0_2)).intValue();
        value |= (0xf << 20);
        unicorn.reg_write(ArmConst.UC_ARM_REG_C1_C0_2, value);
        unicorn.reg_write(ArmConst.UC_ARM_REG_FPEXC, 0x40000000);
    }

    @Override
    protected Debugger createConsoleDebugger() {
        return new SimpleARMDebugger(this);
    }

    @Override
    protected void closeInternal() {
        for (FileIO io : syscallHandler.fdMap.values()) {
            io.close();
        }

        capstoneThumb.close();
        capstoneArm.close();
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
        ARM.showRegs(this, regs);
    }

    @Override
    public Capstone.CsInsn[] printAssemble(PrintStream out, long address, int size) {
        Capstone.CsInsn[] insns = disassemble(address, size, 0);
        printAssemble(out, insns, address, ARM.isThumb(unicorn));
        return insns;
    }

    @Override
    public Capstone.CsInsn[] disassemble(long address, int size, long count) {
        boolean thumb = ARM.isThumb(unicorn);
        byte[] code = unicorn.mem_read(address, size);
        return thumb ? capstoneThumb.disasm(code, address, count) : capstoneArm.disasm(code, address, count);
    }

    @Override
    public Capstone.CsInsn[] disassemble(long address, byte[] code, boolean thumb, long count) {
        return thumb ? capstoneThumb.disasm(code, address, count) : capstoneArm.disasm(code, address, count);
    }

    private void printAssemble(PrintStream out, Capstone.CsInsn[] insns, long address, boolean thumb) {
        StringBuilder sb = new StringBuilder();
        for (Capstone.CsInsn ins : insns) {
            sb.append("### Trace Instruction ");
            sb.append(ARM.assembleDetail(this, ins, address, thumb));
            sb.append('\n');
            address += ins.size;
        }
        out.print(sb.toString());
    }

    @Override
    public Number[] eFunc(long begin, Number... arguments) {
        long spBackup = memory.getStackPoint();
        try {
            unicorn.reg_write(ArmConst.UC_ARM_REG_LR, LR);
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
            unicorn.reg_write(ArmConst.UC_ARM_REG_LR, LR);
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
            unicorn.reg_write(ArmConst.UC_ARM_REG_LR, LR);
            return emulate(begin, LR, timeout, true);
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    @Override
    public Unicorn eBlock(long begin, long until) {
        long spBackup = memory.getStackPoint();
        try {
            unicorn.reg_write(ArmConst.UC_ARM_REG_LR, LR);
            emulate(begin, until, traceInstruction ? 0 : timeout, true);
            return unicorn;
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    @Override
    public int getPointerSize() {
        return 4;
    }

    @Override
    public int getPageAlign() {
        return PAGE_ALIGN;
    }

    @Override
    protected Pointer getStackPointer() {
        return UnicornPointer.register(this, ArmConst.UC_ARM_REG_SP);
    }
}
