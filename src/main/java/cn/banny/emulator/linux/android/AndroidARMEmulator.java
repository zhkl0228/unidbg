package cn.banny.emulator.linux.android;

import capstone.Capstone;
import cn.banny.emulator.arm.ARM;
import cn.banny.emulator.arm.ARMEmulator;
import cn.banny.emulator.arm.AbstractARMEmulator;
import cn.banny.emulator.arm.Arguments;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornConst;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * android arm emulator
 * Created by zhkl0228 on 2017/5/2.
 */

public class AndroidARMEmulator extends AbstractARMEmulator implements ARMEmulator {

    private static final Log log = LogFactory.getLog(AndroidARMEmulator.class);

    private final Capstone capstoneArm, capstoneThumb;
    public static final long LR = 0xffff0000L;

    public AndroidARMEmulator() {
        this(null);
    }

    public AndroidARMEmulator(String processName) {
        super(processName);

        this.capstoneArm = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_ARM);
        // this.capstoneArm.setDetail(Capstone.CS_OPT_ON);
        this.capstoneThumb = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB);
        // this.capstoneThumb.setDetail(Capstone.CS_OPT_ON);

        setupTraps();
    }

    @Override
    protected byte[] assemble(Iterable<String> assembly) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
            KeystoneEncoded encoded = keystone.assemble(assembly);
            return encoded.getMachineCode();
        }
    }

    /**
     * https://github.com/lunixbochs/usercorn/blob/master/go/arch/arm/linux.go
     */
    private void setupTraps() {
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

            encoded = keystone.assemble("bx lr", 0xffff0fa0);
            byte[] __kuser_memory_barrier = encoded.getMachineCode();

            encoded = keystone.assemble(Arrays.asList(
                    "dmb sy",
                    "ldrex r3, [r2]",
                    "subs r3, r3, r0",
                    "strexeq r3, r1, [r2]",
                    "teqeq r3, #1",
                    "beq #0xffff0fc4",
                    "rsbs r0, r3, #0",
                    "b #0xffff0fa0"), 0xffff0fc0);
            byte[] __kuser_cmpxchg = encoded.getMachineCode();
            unicorn.mem_write(0xffff0fa0L, __kuser_memory_barrier);
            unicorn.mem_write(0xffff0fc0L, __kuser_cmpxchg);

            if (log.isDebugEnabled()) {
                log.debug("__kuser_memory_barrier");
                for (int i = 0; i < __kuser_memory_barrier.length; i += 4) {
                    printAssemble(0xffff0fa0L + i, 4);
                }
                log.debug("__kuser_cmpxchg");
                for (int i = 0; i < __kuser_cmpxchg.length; i += 4) {
                    printAssemble(0xffff0fc0L + i, 4);
                }
            }
        }
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
    protected void closeInternal() {
        super.closeInternal();

        capstoneThumb.close();
        capstoneArm.close();
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

        unicorn.reg_write(ArmConst.UC_ARM_REG_LR, LR);
        final List<Number> numbers = new ArrayList<>(10);
        numbers.add(emulate(begin, LR, timeout, true));
        numbers.addAll(args.pointers);
        return numbers.toArray(new Number[0]);
    }

    @Override
    public void eInit(long begin) {
        unicorn.reg_write(ArmConst.UC_ARM_REG_LR, LR);
        emulate(begin, LR, timeout, false);
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
    public void showRegs() {
        this.showRegs((int[]) null);
    }

    @Override
    public void showRegs(int... regs) {
        ARM.showRegs(unicorn, regs);
    }

}
