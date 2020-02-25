package com.github.unidbg.arm;

import capstone.Arm;
import capstone.Capstone;
import com.github.unidbg.Emulator;
import com.github.unidbg.hook.InterceptCallback;
import com.github.unidbg.memory.SvcMemory;
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
public class ArmIntercept extends ArmSvc {

    private final Pointer pointer;
    private final InterceptCallback callback;
    private final Capstone.CsInsn insn;

    ArmIntercept(Pointer pointer, InterceptCallback callback, Capstone.CsInsn insn) {
        this.pointer = pointer;
        this.callback = callback;
        this.insn = insn;
    }

    @Override
    public UnicornPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
            KeystoneEncoded encoded = keystone.assemble("svc #0x" + Integer.toHexString(svcNumber));
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
        if ("push".equals(insn.mnemonic)) {
            evalPush(u, emulator);
        } else {
            throw new UnicornException(insn.mnemonic + " " + insn.opStr);
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
