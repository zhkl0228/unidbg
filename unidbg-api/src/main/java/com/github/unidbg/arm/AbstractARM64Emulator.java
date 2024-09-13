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
import com.github.unidbg.arm.context.BackendArm64RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.file.NewFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.Dlfcn;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.thread.Entry;
import com.github.unidbg.thread.Function64;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.unwind.SimpleARM64Unwinder;
import com.github.unidbg.unwind.Unwinder;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

import java.io.File;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public abstract class AbstractARM64Emulator<T extends NewFileIO> extends AbstractEmulator<T> implements ARMEmulator<T> {

    private static final Logger log = LoggerFactory.getLogger(AbstractARM64Emulator.class);

    protected final Memory memory;
    private final UnixSyscallHandler<T> syscallHandler;

    private static final long LR = 0x7ffff0000L;

    private final Dlfcn dlfcn;

    public AbstractARM64Emulator(String processName, File rootDir, Family family, Collection<BackendFactory> backendFactories, String... envs) {
        super(true, processName, 0xfffe0000L, 0x10000, rootDir, family, backendFactories);

        backend.switchUserMode();

        backend.hook_add_new(new EventMemHook() {
            @Override
            public boolean hook(Backend backend, long address, int size, long value, Object user, UnmappedType unmappedType) {
                log.warn("{} memory failed: address=0x{}, size={}, value=0x{}", unmappedType, Long.toHexString(address), size, Long.toHexString(value));
                if (LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
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

    private Disassembler arm64DisassemblerCache;
    private final Map<Long, Instruction[]> disassembleCache = new HashMap<>();

    private synchronized Disassembler createArm64Disassembler() {
        if (arm64DisassemblerCache == null) {
            this.arm64DisassemblerCache = DisassemblerFactory.createArm64Disassembler();
            this.arm64DisassemblerCache.setDetail(true);
        }
        return arm64DisassemblerCache;
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

            @Override
            protected void dumpGPBProtobufMsg(String className) {
                AbstractARM64Emulator.this.dumpGPBProtobufMsg(className);
            }
        };
    }

    @Override
    protected void closeInternal() {
        syscallHandler.destroy();

        IOUtils.close(arm64DisassemblerCache);
        disassembleCache.clear();
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
    public Instruction[] printAssemble(PrintStream out, long address, int size, int maxLengthLibraryName, InstructionVisitor visitor) {
        Instruction[] insns = disassembleCache.get(address);
        byte[] currentCode = backend.mem_read(address, size);
        boolean needUpdateCache = false;
        if (insns != null) {
            byte[] cachedCode = new byte[size];
            int offset = 0;
            for (Instruction insn : insns) {
                byte[] insnBytes = insn.getBytes();
                System.arraycopy(insnBytes, 0, cachedCode, offset, insnBytes.length);
                offset += insnBytes.length;
            }

            if (!Arrays.equals(currentCode, cachedCode)) {
                needUpdateCache = true;
            }
        } else {
            needUpdateCache = true;
        }
        if (needUpdateCache) {
            insns = disassemble(address, currentCode, false, 0);
            disassembleCache.put(address, insns);
        }
        printAssemble(out, insns, address, maxLengthLibraryName, visitor);
        return insns;
    }

    @Override
    public Instruction[] disassemble(long address, int size, long count) {
        byte[] code = backend.mem_read(address, size);
        return createArm64Disassembler().disasm(code, address, count);
    }

    @Override
    public Instruction[] disassemble(long address, byte[] code, boolean thumb, long count) {
        if (thumb) {
            throw new IllegalStateException();
        }
        return createArm64Disassembler().disasm(code, address, count);
    }

    private void printAssemble(PrintStream out, Instruction[] insns, long address, int maxLengthLibraryName, InstructionVisitor visitor) {
        StringBuilder builder = new StringBuilder();
        for (Instruction ins : insns) {
            if(visitor != null) {
                visitor.visitLast(builder);
            }
            builder.append('\n');
            builder.append(dateFormat.format(new Date()));
            builder.append(ARM.assembleDetail(this, ins, address, false, maxLengthLibraryName));
            if (visitor != null) {
                visitor.visit(builder, ins);
            }
            address += ins.getSize();
        }
        out.print(builder);
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
    public Number eFunc(long begin, Number... arguments) {
        return runMainForResult(new Function64(getPid(), begin, LR, isPaddingArgument(), arguments));
    }

    @Override
    public Number eEntry(long begin, long sp) {
        return runMainForResult(new Entry(getPid(), begin, LR, sp));
    }

    @Override
    public Pointer getStackPointer() {
        return UnidbgPointer.register(this, Arm64Const.UC_ARM64_REG_SP);
    }

    @Override
    public Unwinder getUnwinder() {
        return new SimpleARM64Unwinder(this);
    }

    @Override
    public long getReturnAddress() {
        return LR;
    }
}
