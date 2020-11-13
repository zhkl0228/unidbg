package com.github.unidbg.arm;

import capstone.Arm;
import capstone.Capstone;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.hook.InterceptCallback;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.ArmConst;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

class ArmIntercept extends ArmSvc {

    private final Pointer pointer;
    private final InterceptCallback callback;
    private final Capstone.CsInsn insn;

    ArmIntercept(Pointer pointer, InterceptCallback callback, Capstone.CsInsn insn) {
        this.pointer = pointer;
        this.callback = callback;
        this.insn = insn;
    }

    @Override
    public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
            KeystoneEncoded encoded = keystone.assemble("svc #0x" + Integer.toHexString(svcNumber));
            byte[] code = encoded.getMachineCode();
            pointer.write(0, code, 0, code.length);
            return null;
        }
    }

    @Override
    public long handle(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        if (callback != null) {
            callback.onIntercept(emulator);
        }
        eval(backend, emulator);
        return backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
    }

    private void eval(Backend backend, Emulator<?> emulator) {
        if ("push".equals(insn.mnemonic)) {
            evalPush(backend, emulator);
        } else {
            throw new BackendException(insn.mnemonic + " " + insn.opStr);
        }
    }

    private void evalPush(Backend backend, Emulator<?> emulator) {
        Pointer sp = UnidbgPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
        Arm.OpInfo opInfo = (Arm.OpInfo) this.insn.operands;
        List<Arm.Operand> operandList = new ArrayList<>(opInfo.op.length);
        Collections.addAll(operandList, opInfo.op);
        Collections.reverse(operandList);
        try {
            for (Arm.Operand operand : operandList) {
                sp = sp.share(-4);
                sp.setPointer(0, UnidbgPointer.register(emulator, operand.value.reg));
            }
        } finally {
            backend.reg_write(ArmConst.UC_ARM_REG_SP, ((UnidbgPointer) sp).peer);
        }
    }

}
