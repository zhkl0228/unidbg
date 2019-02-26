package cn.banny.emulator.linux.android;

import capstone.Capstone;
import cn.banny.emulator.arm.ARM;
import cn.banny.emulator.arm.ARMEmulator;
import cn.banny.emulator.arm.AbstractARM64Emulator;
import cn.banny.emulator.arm.Arguments;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * android arm emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public class AndroidARM64Emulator extends AbstractARM64Emulator implements ARMEmulator {

    private static final Log log = LogFactory.getLog(AndroidARM64Emulator.class);

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
        int i = 0;
        int[] regArgs = ARM.getRegArgs(this);
        final Arguments args = new Arguments(this.memory, arguments);

        List<Number> list = new ArrayList<>();
        if (args.args != null) {
            Collections.addAll(list, args.args);
        }
        while (!list.isEmpty() && i < regArgs.length) {
            unicorn.reg_write(regArgs[i], list.remove(0));
            i++;
        }
        Collections.reverse(list);
        while (!list.isEmpty()) {
            Number number = list.remove(0);
            Pointer pointer = memory.allocateStack(4);
            assert pointer != null;
            pointer.setInt(0, number.intValue());
        }

        unicorn.reg_write(Arm64Const.UC_ARM64_REG_LR, LR);
        final List<Number> numbers = new ArrayList<>(10);
        numbers.add(emulate(begin, LR, timeout, true));
        numbers.addAll(args.pointers);
        return numbers.toArray(new Number[0]);
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

    @Override
    public void showRegs() {
        this.showRegs((int[]) null);
    }

    @Override
    public void showRegs(int... regs) {
        ARM.showRegs64(unicorn, regs);
    }

}
