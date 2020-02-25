package com.github.unidbg.arm;

import capstone.Arm;
import capstone.Arm_const;
import capstone.Capstone;
import com.github.unidbg.Emulator;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.hook.InterceptCallback;
import com.github.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Use HookZz
 */
public class ThumbIntercept extends ThumbSvc {

    private final Pointer pointer;
    private final InterceptCallback callback;
    private final Capstone.CsInsn insn;
    private final boolean isThumb32;

    ThumbIntercept(Pointer pointer, InterceptCallback callback, Capstone.CsInsn insn, boolean isThumb32) {
        this.pointer = pointer;
        this.callback = callback;
        this.insn = insn;
        this.isThumb32 = isThumb32;
    }

    @Override
    public UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        if (svcNumber < 0 || svcNumber > 0xff) {
            throw new IllegalStateException("service number out of range");
        }

        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.ArmThumb)) {
            List<String> asm = new ArrayList<>(2);
            asm.add("svc #0x" + Integer.toHexString(svcNumber));
            if (isThumb32) {
                if ("bl".equals(insn.mnemonic)) {
                    asm.add("pop {pc}");
                } else {
                    asm.add("nop");
                }
            }
            KeystoneEncoded encoded = keystone.assemble(asm);
            byte[] code = encoded.getMachineCode();
            pointer.write(0, code, 0, code.length);
            return null;
        }
    }

    @Override
    public long handle(Emulator<?> emulator) {
        Unicorn u = emulator.getUnicorn();
        if (callback != null) {
            callback.onIntercept(emulator);
        }
        eval(u, emulator);
        return ((Number) u.reg_read(ArmConst.UC_ARM_REG_R0)).intValue();
    }

    private void eval(Unicorn u, Emulator<?> emulator) {
        switch (insn.mnemonic) {
            case "push":
                evalPush(u, emulator);
                break;
            case "mul":
            case "muls":
                evalMul(u);
                break;
            case "sub":
            case "subs":
                evalSub(u);
                break;
            case "add":
                evalAdd(u);
                break;
            case "bl":
                evalBL(u, false, emulator);
                break;
            case "blx":
                evalBL(u, true, emulator);
                break;
            default:
                throw new UnicornException(insn.mnemonic + " " + insn.opStr);
        }
    }

    private void evalBL(Unicorn u, boolean x, Emulator<?> emulator) {
        Pointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        try {
            Pointer pc = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_PC);
            u.reg_write(ArmConst.UC_ARM_REG_LR, ((UnicornPointer) pc.share(2)).peer | 1L); // thumb
            sp = sp.share(-4);

            Arm.OpInfo opInfo = (Arm.OpInfo) this.insn.operands;
            int off = opInfo.op[0].value.imm;
            pc = pc.share(off).share(-2);
            if (!x) {
                pc = pc.share(1); // thumb
            }
            sp.setPointer(0, pc);
        } finally {
            u.reg_write(ArmConst.UC_ARM_REG_SP, ((UnicornPointer) sp).peer);
        }
    }

    private void evalAdd(Unicorn u) {
        Arm.OpInfo opInfo = (Arm.OpInfo) this.insn.operands;
        int opCount = opInfo.op.length;
        if (opCount != 2 && opCount != 3) {
            throw new UnicornException("opCount=" + opCount);
        }

        long o1 = ((Number) u.reg_read(opInfo.op[opCount - 2].value.reg)).intValue() & 0xffffffffL;
        long o2 = getOperandValue(u, opInfo.op[opCount - 1]) & 0xffffffffL;
        long result = o1 + o2;
        u.reg_write(opInfo.op[0].value.reg, (int) result);
        if (opInfo.updateFlags) {
            Cpsr cpsr = Cpsr.getArm(u);
            cpsr.setNegative((int) result < 0);
            cpsr.setZero(result == 0);
            cpsr.setCarry(result >= 0x100000000L);
            boolean overflow = ((int) o1 >= 0 && (int) o2 >= 0 && (int) result < 0) || ((int) o1 < 0 && (int) o2 < 0 && (int) result >= 0);
            cpsr.setOverflow(overflow);
        }
    }

    private void evalSub(Unicorn u) {
        Arm.OpInfo opInfo = (Arm.OpInfo) this.insn.operands;
        int opCount = opInfo.op.length;
        if (opCount != 2 && opCount != 3) {
            throw new UnicornException("opCount=" + opCount);
        }

        int o1 = ((Number) u.reg_read(opInfo.op[opCount - 2].value.reg)).intValue();
        int o2 = getOperandValue(u, opInfo.op[opCount - 1]);
        int result = o1 - o2;
        u.reg_write(opInfo.op[0].value.reg, result);
        if (opInfo.updateFlags) {
            Cpsr cpsr = Cpsr.getArm(u);
            cpsr.setNegative(result < 0);
            cpsr.setZero(result == 0);
            cpsr.setCarry(result >= 0);
            boolean overflow = (o1 >= 0 && o2 < 0 && result < 0) || (o1 < 0 && o2 >= 0 && result >= 0);
            cpsr.setOverflow(overflow);
        }
    }

    private int getOperandValue(Unicorn u, Arm.Operand op) {
        switch (op.type) {
            case capstone.Arm_const.ARM_OP_REG:
                int value = ((Number) u.reg_read(op.value.reg)).intValue();
                if (op.value.reg == ArmConst.UC_ARM_REG_PC) {
                    value += 2;
                }
                return value;
            case Arm_const.ARM_OP_IMM:
                return op.value.imm;
            default:
                throw new UnicornException("op.type=" + op.type);
        }
    }

    private void evalMul(Unicorn u) {
        Arm.OpInfo opInfo = (Arm.OpInfo) this.insn.operands;
        int opCount = opInfo.op.length;
        if (opCount != 2 && opCount != 3) {
            throw new UnicornException("opCount=" + opCount);
        }
        long o1 = ((Number) u.reg_read(opInfo.op[opCount - 2].value.reg)).intValue() & 0xffffffffL;
        long o2 = ((Number) u.reg_read(opInfo.op[opCount - 1].value.reg)).intValue() & 0xffffffffL;
        int result = (int) (o1 * o2);
        u.reg_write(opInfo.op[0].value.reg, result);
        if (opInfo.updateFlags) {
            Cpsr cpsr = Cpsr.getArm(u);
            cpsr.setNegative(result < 0);
            cpsr.setZero(result == 0);
        }
    }

    private void evalPush(Unicorn u, Emulator<?> emulator) {
        Pointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        Arm.OpInfo opInfo = (Arm.OpInfo) this.insn.operands;
        List<Arm.Operand> operandList = new ArrayList<>(opInfo.op.length);
        Collections.addAll(operandList, opInfo.op);
        Collections.reverse(operandList);
        try {
            for (Arm.Operand operand : operandList) {
                sp = sp.share(-4);
                sp.setPointer(0, UnicornPointer.register(emulator, operand.value.reg));
            }
        } finally {
            u.reg_write(ArmConst.UC_ARM_REG_SP, ((UnicornPointer) sp).peer);
        }
    }

}
