package cn.banny.emulator.linux.android;

import capstone.Capstone;
import cn.banny.emulator.arm.ARM;
import cn.banny.emulator.arm.ARMEmulator;
import cn.banny.emulator.arm.AbstractARM64Emulator;
import cn.banny.emulator.arm.Arguments;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.Arm64Const;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.nio.ByteBuffer;

/**
 * android arm emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public class AndroidARM64Emulator extends AbstractARM64Emulator implements ARMEmulator {

    private final Capstone capstoneArm64;
    private static final long LR = 0xffffffffffff0000L;

    public AndroidARM64Emulator() {
        this(null);
    }

    public AndroidARM64Emulator(String processName) {
        super(processName);

        this.capstoneArm64 = new Capstone(Capstone.CS_ARCH_ARM64, Capstone.CS_MODE_ARM);

        setupTraps();
    }

    @Override
    protected byte[] assemble(Iterable<String> assembly) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            KeystoneEncoded encoded = keystone.assemble(assembly);
            return encoded.getMachineCode();
        }
    }

    /**
     * https://github.com/lunixbochs/usercorn/blob/master/go/arch/arm/linux.go
     */
    private void setupTraps() {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            unicorn.mem_map(LR, 0x10000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
            KeystoneEncoded encoded = keystone.assemble("b #0");
            byte[] b0 = encoded.getMachineCode();
            ByteBuffer buffer = ByteBuffer.allocate(0x10000);
            for (int i = 0; i < 0x10000; i += b0.length) {
                buffer.put(b0);
            }
            unicorn.mem_write(LR, buffer.array());
        }
    }

    @Override
    public boolean printAssemble(long address, int size) {
        printAssemble(disassemble(address, size, 0), address);
        return true;
    }

    @Override
    public Capstone.CsInsn[] disassemble(long address, int size, long count) {
        byte[] code = unicorn.mem_read(address, size);
        return capstoneArm64.disasm(code, address, count);
    }

    @Override
    public Capstone.CsInsn[] disassemble(long address, byte[] code, boolean thumb) {
        if (thumb) {
            throw new IllegalStateException();
        }
        return capstoneArm64.disasm(code, address);
    }

    private void printAssemble(Capstone.CsInsn[] insns, long address) {
        StringBuilder sb = new StringBuilder();
        for (Capstone.CsInsn ins : insns) {
            sb.append("### Trace Instruction ");
            sb.append(ARM.assembleDetail(memory, ins, address, false));
            sb.append('\n');
            address += ins.size;
        }
        System.out.print(sb.toString());
    }

    @Override
    protected void closeInternal() {
        super.closeInternal();

        capstoneArm64.close();
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
        unicorn.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
        final Arguments args = ARM.initArgs(this, arguments);
        return eFunc(begin, args, LR);
    }

    @Override
    public void eInit(long begin) {
        unicorn.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
        emulate(begin, LR, timeout, false);
    }

    @Override
    public Number eEntry(long begin, long sp) {
        memory.setStackPoint(sp);
        unicorn.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
        return emulate(begin, LR, timeout, true);
    }

    @Override
    public Unicorn eBlock(long begin, long until) {
        unicorn.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
        emulate(begin, until, traceInstruction ? 0 : timeout, true);
        return unicorn;
    }

}
