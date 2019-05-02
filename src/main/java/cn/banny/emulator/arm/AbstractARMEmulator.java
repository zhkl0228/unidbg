package cn.banny.emulator.arm;

import capstone.Capstone;
import cn.banny.emulator.AbstractEmulator;
import cn.banny.emulator.spi.Dlfcn;
import cn.banny.emulator.unix.UnixSyscallHandler;
import cn.banny.emulator.Module;
import cn.banny.emulator.spi.SyscallHandler;
import cn.banny.emulator.debugger.Debugger;
import cn.banny.emulator.file.FileIO;
import cn.banny.emulator.memory.Memory;
import cn.banny.emulator.memory.SvcMemory;
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
import java.nio.ByteBuffer;

public abstract class AbstractARMEmulator extends AbstractEmulator implements ARMEmulator {

    private static final Log log = LogFactory.getLog(AbstractARMEmulator.class);

    public static final long LR = 0xffff0000L;

    protected final Memory memory;
    private final UnixSyscallHandler syscallHandler;
    private final SvcMemory svcMemory;

    private final Capstone capstoneArm, capstoneThumb;

    private final Dlfcn dlfcn;

    public AbstractARMEmulator(String processName) {
        super(UnicornConst.UC_ARCH_ARM, UnicornConst.UC_MODE_ARM, processName);

        Cpsr.getArm(unicorn).switchUserMode();

        unicorn.hook_add(new EventMemHook() {
            @Override
            public boolean hook(Unicorn u, long address, int size, long value, Object user) {
                log.debug("memory failed: address=0x" + Long.toHexString(address) + ", size=" + size + ", value=0x" + Long.toHexString(value) + ", user=" + user);
                return false;
            }
        }, UnicornConst.UC_HOOK_MEM_READ_UNMAPPED | UnicornConst.UC_HOOK_MEM_WRITE_UNMAPPED | UnicornConst.UC_HOOK_MEM_FETCH_UNMAPPED, null);

        this.svcMemory = new ARMSvcMemory(unicorn, 0xfffe0000L, 0x10000, this);
        this.syscallHandler = createSyscallHandler(svcMemory);

        enableVFP();
        this.memory = createMemory(syscallHandler);
        this.dlfcn = createDyld(svcMemory);
        this.memory.addHookListener(dlfcn);

        unicorn.hook_add(syscallHandler, this);

        this.capstoneArm = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_ARM);
        // this.capstoneArm.setDetail(Capstone.CS_OPT_ON);
        this.capstoneThumb = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB);
        // this.capstoneThumb.setDetail(Capstone.CS_OPT_ON);

        setupTraps();
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
    protected Debugger createDebugger() {
        return new SimpleARMDebugger();
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

    public SvcMemory getSvcMemory() {
        return svcMemory;
    }

    @Override
    public Memory getMemory() {
        return memory;
    }

    @Override
    public SyscallHandler getSyscallHandler() {
        return syscallHandler;
    }

    @Override
    public final void showRegs() {
        this.showRegs((int[]) null);
    }

    @Override
    public final void showRegs(int... regs) {
        ARM.showRegs(unicorn, regs);
    }

    @Override
    public boolean printAssemble(long address, int size) {
        printAssemble(disassemble(address, size, 0), address, ARM.isThumb(unicorn));
        return true;
    }

    @Override
    public Capstone.CsInsn[] disassemble(long address, int size, long count) {
        boolean thumb = ARM.isThumb(unicorn);
        byte[] code = unicorn.mem_read(address, size);
        return thumb ? capstoneThumb.disasm(code, address, count) : capstoneArm.disasm(code, address, count);
    }

    @Override
    public Capstone.CsInsn[] disassemble(long address, byte[] code, boolean thumb) {
        return thumb ? capstoneThumb.disasm(code, address) : capstoneArm.disasm(code, address);
    }

    private void printAssemble(Capstone.CsInsn[] insns, long address, boolean thumb) {
        StringBuilder sb = new StringBuilder();
        for (Capstone.CsInsn ins : insns) {
            sb.append("### Trace Instruction ");
            sb.append(ARM.assembleDetail(memory, ins, address, thumb));
            sb.append('\n');
            address += ins.size;
        }
        System.out.print(sb.toString());
    }

    @Override
    public Number[] eFunc(long begin, Number... arguments) {
        unicorn.reg_write(ArmConst.UC_ARM_REG_LR, LR);
        final Arguments args = ARM.initArgs(this, arguments);
        return eFunc(begin, args, LR, true);
    }

    @Override
    public void eInit(long begin, Number... arguments) {
        unicorn.reg_write(ArmConst.UC_ARM_REG_LR, LR);
        final Arguments args = ARM.initArgs(this, arguments);
        eFunc(begin, args, LR, false);
    }

    @Override
    public Number eEntry(long begin, long sp) {
        memory.setStackPoint(sp);
        unicorn.reg_write(ArmConst.UC_ARM_REG_LR, LR);
        return emulate(begin, LR, timeout, true);
    }

    @Override
    public Unicorn eBlock(long begin, long until) {
        unicorn.reg_write(ArmConst.UC_ARM_REG_LR, LR);
        emulate(begin, until, traceInstruction ? 0 : timeout, true);
        return unicorn;
    }

    @Override
    public int getPointerSize() {
        return 4;
    }

    @Override
    public int getPageAlign() {
        return PAGE_ALIGN;
    }

}
