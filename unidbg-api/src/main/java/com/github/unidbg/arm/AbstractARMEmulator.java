package com.github.unidbg.arm;

import capstone.api.Disassembler;
import capstone.api.DisassemblerFactory;
import capstone.api.Instruction;
import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Family;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.EventMemHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.context.BackendArm32RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.thread.Entry;
import com.github.unidbg.thread.Function32;
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
import java.util.Date;

public abstract class AbstractARMEmulator<T extends NewFileIO> extends AbstractEmulator<T> implements ARMEmulator<T> {

    private static final Log log = LogFactory.getLog(AbstractARMEmulator.class);

    private static final long LR = 0xffff0000L;

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
                if (LogFactory.getLog(AbstractEmulator.class).isDebugEnabled()) {
                    attach().debug();
                }
                return false;
            }
            @Override
            public void onAttach(UnHook unHook) {
            }
            @Override
            public void detach() {
                throw new UnsupportedOperationException();
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

    private Disassembler armDisassemblerCache, thumbDisassemblerCache;

    private synchronized Disassembler createThumbCapstone() {
        if (thumbDisassemblerCache == null) {
            this.thumbDisassemblerCache = DisassemblerFactory.createArmDisassembler(true);
            this.thumbDisassemblerCache.setDetail(true);
        }
        return thumbDisassemblerCache;
    }

    private synchronized Disassembler createArmCapstone() {
        if (armDisassemblerCache == null) {
            this.armDisassemblerCache = DisassemblerFactory.createArmDisassembler(false);
            this.armDisassemblerCache.setDetail(true);
        }
        return armDisassemblerCache;
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

        IOUtils.close(thumbDisassemblerCache);
        IOUtils.close(armDisassemblerCache);
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
    public Instruction[] printAssemble(PrintStream out, long address, int size, InstructionVisitor visitor) {
        Instruction[] insns = disassemble(address, size, 0);
        printAssemble(out, insns, address, ARM.isThumb(backend), visitor);
        return insns;
    }

    @Override
    public Instruction[] disassemble(long address, int size, long count) {
        boolean thumb = ARM.isThumb(backend);
        byte[] code = backend.mem_read(address, size);
        return thumb ? createThumbCapstone().disasm(code, address, count) : createArmCapstone().disasm(code, address, count);
    }

    @Override
    public Instruction[] disassemble(long address, byte[] code, boolean thumb, long count) {
        return thumb ? createThumbCapstone().disasm(code, address, count) : createArmCapstone().disasm(code, address, count);
    }

    private void printAssemble(PrintStream out, Instruction[] insns, long address, boolean thumb, InstructionVisitor visitor) {
        StringBuilder sb = new StringBuilder();
        for (Instruction ins : insns) {
            sb.append(dateFormat.format(new Date())).append(" Trace Instruction ");
            sb.append(ARM.assembleDetail(this, ins, address, thumb));
            if (visitor != null) {
                visitor.visit(sb, ins);
            }
            sb.append('\n');
            address += ins.getSize();
        }
        out.print(sb);
    }

    @Override
    public Number[] eFunc(long begin, Number... arguments) {
        long spBackup = memory.getStackPoint();
        try {
            return new Number[] {
                    getThreadDispatcher().runMainForResult(new Function32(begin, LR, isPaddingArgument(), arguments))
            };
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    @Override
    public Number eEntry(long begin, long sp) {
        long spBackup = memory.getStackPoint();
        try {
            return getThreadDispatcher().runMainForResult(new Entry(begin, LR, sp));
        } finally {
            memory.setStackPoint(spBackup);
        }
    }

    @Override
    public void eThread(long fn, long arg, long sp) {
        backend.reg_write(ArmConst.UC_ARM_REG_R0, arg);
        backend.reg_write(ArmConst.UC_ARM_REG_SP, sp);
        emulate(fn, LR, timeout);
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
    public Pointer getStackPointer() {
        return UnidbgPointer.register(this, ArmConst.UC_ARM_REG_SP);
    }

    @Override
    public Unwinder getUnwinder() {
        return new SimpleARMUnwinder(this);
    }

    @Override
    public long getReturnAddress() {
        return LR;
    }
}
