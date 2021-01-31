package com.github.unidbg.arm;

import capstone.Capstone;
import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Family;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.EventMemHook;
import com.github.unidbg.arm.context.BackendArm32RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.unwind.SimpleARMUnwinder;
import com.github.unidbg.unwind.Unwinder;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;
import unicorn.UnicornConst;

import java.io.File;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Collection;

public abstract class AbstractARMEmulator<T extends NewFileIO> extends AbstractEmulator<T> implements ARMEmulator<T> {

    private static final Log log = LogFactory.getLog(AbstractARMEmulator.class);

    public static final long LR = 0xffff0000L;

    protected final Memory memory;
    private final UnixSyscallHandler<T> syscallHandler;

    private final Dlfcn dlfcn;

    public AbstractARMEmulator(String processName, File rootDir, Family family, Collection<BackendFactory> backendFactories, String... envs) {
        super(false, processName, 0xfffe0000L, 0x10000, rootDir, family, backendFactories);

        backend.switchUserMode();

        backend.hook_add_new(new EventMemHook() {
            @Override
            public boolean hook(Backend backend, long address, int size, long value, Object user) {
                RegisterContext context = getContext();
                log.warn("memory failed: address=0x" + Long.toHexString(address) + ", size=" + size + ", value=0x" + Long.toHexString(value) + ", PC=" + context.getPCPointer() + ", LR=" + context.getLRPointer());
                return false;
            }
        }, UnicornConst.UC_HOOK_MEM_READ_UNMAPPED | UnicornConst.UC_HOOK_MEM_WRITE_UNMAPPED | UnicornConst.UC_HOOK_MEM_FETCH_UNMAPPED, null);

        this.syscallHandler = createSyscallHandler(svcMemory);

        backend.enableVFP();
        this.memory = createMemory(syscallHandler, envs);
        this.dlfcn = createDyld(svcMemory);
        this.memory.addHookListener(dlfcn);

        backend.hook_add_new(syscallHandler, this);

        setupTraps();
    }

    private Capstone capstoneArmCache, capstoneThumbCache;

    private synchronized Capstone createThumbCapstone() {
        if (capstoneThumbCache == null) {
            this.capstoneThumbCache = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB);
            this.capstoneThumbCache.setDetail(Capstone.CS_OPT_ON);
        }
        return capstoneThumbCache;
    }

    private synchronized Capstone createArmCapstone() {
        if (capstoneArmCache == null) {
            this.capstoneArmCache = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_ARM);
            this.capstoneArmCache.setDetail(Capstone.CS_OPT_ON);
        }
        return capstoneArmCache;
    }

    @Override
    protected RegisterContext createRegisterContext(Backend backend) {
        return new BackendArm32RegisterContext(backend, this);
    }

    @Override
    public Dlfcn getDlfcn() {
        return dlfcn;
    }

    protected void setupTraps() {
        int size = 0x10000;
        backend.mem_map(LR, size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
        int code = ArmSvc.assembleSvc(0);
        ByteBuffer buffer = ByteBuffer.allocate(size);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        for (int i = 0; i < size; i += 4) {
            buffer.putInt(code); // svc #0
        }
        memory.pointer(LR).write(buffer.array());
    }

    @Override
    protected final byte[] assemble(Iterable<String> assembly) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
            KeystoneEncoded encoded = keystone.assemble(assembly);
            return encoded.getMachineCode();
        }
    }

    @Override
    protected Debugger createConsoleDebugger() {
        return new SimpleARMDebugger(this) {
            @Override
            protected void dumpClass(String className) {
                AbstractARMEmulator.this.dumpClass(className);
            }
            @Override
            protected void searchClass(String keywords) {
                AbstractARMEmulator.this.searchClass(keywords);
            }
        };
    }

    @Override
    protected void closeInternal() {
        for (FileIO io : syscallHandler.fdMap.values()) {
            io.close();
        }

        if (capstoneThumbCache != null) {
            capstoneThumbCache.close();
        }
        if (capstoneArmCache != null) {
            capstoneArmCache.close();
        }
    }

    @Override
    public Module loadLibrary(File libraryFile) {
        return memory.load(libraryFile);
    }

    @Override
    public Module loadLibrary(File libraryFile, boolean forceCallInit) {
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
        printAssemble(out, insns, address, ARM.isThumb(backend));
        return insns;
    }

    @Override
    public Capstone.CsInsn[] disassemble(long address, int size, long count) {
        boolean thumb = ARM.isThumb(backend);
        byte[] code = backend.mem_read(address, size);
        return thumb ? createThumbCapstone().disasm(code, address, count) : createArmCapstone().disasm(code, address, count);
    }

    @Override
    public Capstone.CsInsn[] disassemble(long address, byte[] code, boolean thumb, long count) {
        return thumb ? createThumbCapstone().disasm(code, address, count) : createArmCapstone().disasm(code, address, count);
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
            backend.reg_write(ArmConst.UC_ARM_REG_LR, LR);
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
            backend.reg_write(ArmConst.UC_ARM_REG_LR, LR);
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
            backend.reg_write(ArmConst.UC_ARM_REG_LR, LR);
            return emulate(begin, LR, timeout, true);
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    @Override
    public void eBlock(long begin, long until) {
        long spBackup = memory.getStackPoint();
        try {
            backend.reg_write(ArmConst.UC_ARM_REG_LR, LR);
            emulate(begin, until, traceInstruction ? 0 : timeout, true);
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    @Override
    public int getPointerSize() {
        return 4;
    }

    @Override
    protected int getPageAlignInternal() {
        return PAGE_ALIGN;
    }

    @Override
    protected Pointer getStackPointer() {
        return UnidbgPointer.register(this, ArmConst.UC_ARM_REG_SP);
    }

    @Override
    public Unwinder getUnwinder() {
        return new SimpleARMUnwinder(this);
    }
}
