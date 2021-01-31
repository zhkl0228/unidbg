package com.github.unidbg.arm;

import capstone.Capstone;
import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Family;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.EventMemHook;
import com.github.unidbg.arm.context.BackendArm64RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.unwind.SimpleARM64Unwinder;
import com.github.unidbg.unwind.Unwinder;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

import java.io.File;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Collection;

public abstract class AbstractARM64Emulator<T extends NewFileIO> extends AbstractEmulator<T> implements ARMEmulator<T> {

    private static final Log log = LogFactory.getLog(AbstractARM64Emulator.class);

    protected final Memory memory;
    private final UnixSyscallHandler<T> syscallHandler;

    public static final long LR = 0x7ffff0000L;

    private final Dlfcn dlfcn;

    public AbstractARM64Emulator(String processName, File rootDir, Family family, Collection<BackendFactory> backendFactories, String... envs) {
        super(true, processName, 0xfffe0000L, 0x10000, rootDir, family, backendFactories);

        backend.switchUserMode();

        backend.hook_add_new(new EventMemHook() {
            @Override
            public boolean hook(Backend backend, long address, int size, long value, Object user) {
                log.warn("memory failed: address=0x" + Long.toHexString(address) + ", size=" + size + ", value=0x" + Long.toHexString(value));
                if (LogFactory.getLog(AbstractEmulator.class).isDebugEnabled()) {
                    attach().debug();
                }
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

    private Capstone capstoneArm64Cache;

    private synchronized Capstone createCapstoneArm64() {
        if (capstoneArm64Cache == null) {
            this.capstoneArm64Cache = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);
            this.capstoneArm64Cache.setDetail(Capstone.CS_OPT_ON);
        }
        return capstoneArm64Cache;
    }

    protected void setupTraps() {
        int size = getPageAlign();
        backend.mem_map(LR, size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
        ByteBuffer buffer = ByteBuffer.allocate(size);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        int code = Arm64Svc.assembleSvc(0);
        for (int i = 0; i < size; i += 4) {
            buffer.putInt(code); // svc #0
        }
        memory.pointer(LR).write(buffer.array());
    }

    @Override
    protected RegisterContext createRegisterContext(Backend backend) {
        return new BackendArm64RegisterContext(backend, this);
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

    @Override
    protected Debugger createConsoleDebugger() {
        return new SimpleARM64Debugger(this) {
            @Override
            protected void dumpClass(String className) {
                AbstractARM64Emulator.this.dumpClass(className);
            }
            @Override
            protected void searchClass(String keywords) {
                AbstractARM64Emulator.this.searchClass(keywords);
            }
        };
    }

    @Override
    protected void closeInternal() {
        for (FileIO io : syscallHandler.fdMap.values()) {
            io.close();
        }

        if (capstoneArm64Cache != null) {
            capstoneArm64Cache.close();
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
        byte[] code = backend.mem_read(address, size);
        return createCapstoneArm64().disasm(code, address, count);
    }

    @Override
    public Capstone.CsInsn[] disassemble(long address, byte[] code, boolean thumb, long count) {
        if (thumb) {
            throw new IllegalStateException();
        }
        return createCapstoneArm64().disasm(code, address, count);
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
    protected int getPageAlignInternal() {
        return PAGE_ALIGN;
    }

    @Override
    public Number[] eFunc(long begin, Number... arguments) {
        long spBackup = memory.getStackPoint();
        try {
            backend.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
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
            backend.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
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
            backend.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
            return emulate(begin, LR, timeout, true);
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    @Override
    public void eBlock(long begin, long until) {
        long spBackup = memory.getStackPoint();
        try {
            backend.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
            emulate(begin, until, traceInstruction ? 0 : timeout, true);
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    @Override
    protected Pointer getStackPointer() {
        return UnidbgPointer.register(this, Arm64Const.UC_ARM64_REG_SP);
    }

    @Override
    public Unwinder getUnwinder() {
        return new SimpleARM64Unwinder(this);
    }
}
