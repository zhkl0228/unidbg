package com.github.unidbg.arm;

import capstone.Capstone;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.hook.HookCallback;
import com.github.unidbg.hook.InterceptCallback;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.ArmConst;

import java.util.Arrays;

/**
 * Use debugger
 */
@SuppressWarnings("unused")
public class InlineHook {

    /**
     * 只能hook thumb指令: PUSH {R4-R7,LR}，即函数入口
     */
    public static void simpleThumbHook(Emulator<?> emulator, long address, final HookCallback callback) {
        final Backend backend = emulator.getBackend();
        final Pointer pointer = UnidbgPointer.pointer(emulator, address);
        if (pointer == null) {
            throw new IllegalArgumentException();
        }
        Capstone capstone = null;
        try {
            capstone = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB);
            capstone.setDetail(Capstone.CS_OPT_ON);

            byte[] code = readThumbCode(pointer);
            Capstone.CsInsn[] insns = capstone.disasm(code, 0, 1);
            if (insns == null || insns.length < 1) {
                throw new IllegalArgumentException("Invalid hook address: " + pointer);
            }
            Capstone.CsInsn insn = insns[0];
            String asm = insn.mnemonic + " " + insn.opStr;
            if (!"push {r4, r5, r6, r7, lr}".equals(asm)) {
                throw new IllegalArgumentException("Invalid hook address: " + pointer + ", asm: " + asm);
            }

            emulator.getSvcMemory().registerSvc(new ThumbSvc() {
                @Override
                public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                    if (svcNumber < 0 || svcNumber > 0xff) {
                        throw new IllegalStateException("service number out of range");
                    }

                    try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.ArmThumb)) {
                        KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                "svc #0x" + Integer.toHexString(svcNumber),
                                "mov pc, lr"));
                        byte[] code = encoded.getMachineCode();
                        pointer.write(0, code, 0, code.length);
                        return null;
                    }
                }
                @Override
                public long handle(Emulator<?> emulator) {
                    if (callback != null) {
                        return callback.onHook(emulator);
                    }
                    return backend.reg_read(ArmConst.UC_ARM_REG_R0).intValue();
                }
            });
        } finally {
            if (capstone != null) {
                capstone.close();
            }
        }
    }

    /**
     * 只能hook arm指令：STMFD SP!, {R4-R9,LR}或STMFD SP!, {R4-R11,LR}，即函数入口
     */
    public static void simpleArmHook(Emulator<?> emulator, long address, final HookCallback callback) {
        final Pointer pointer = UnidbgPointer.pointer(emulator, address);
        if (pointer == null) {
            throw new IllegalArgumentException();
        }
        Capstone capstone = null;
        try {
            capstone = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_ARM);
            capstone.setDetail(Capstone.CS_OPT_ON);

            byte[] code = pointer.getByteArray(0, 4);
            Capstone.CsInsn[] insns = capstone.disasm(code, 0, 1);
            if (insns == null || insns.length < 1) {
                throw new IllegalArgumentException("Invalid hook address: " + pointer);
            }
            Capstone.CsInsn insn = insns[0];
            String asm = insn.mnemonic + " " + insn.opStr;
            if (!"push {r4, r5, r6, r7, r8, sb, lr}".equals(asm) && !"push {r4, r5, r6, r7, r8, sb, sl, fp, lr}".equals(asm)) {
                throw new IllegalArgumentException("Invalid hook address: " + pointer + ", asm: " + asm);
            }

            emulator.getSvcMemory().registerSvc(new ArmSvc() {
                @Override
                public UnidbgPointer onRegister(SvcMemory svcMemory, int svcNumber) {
                    try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm, KeystoneMode.Arm)) {
                        KeystoneEncoded encoded = keystone.assemble(Arrays.asList(
                                "svc #0x" + Integer.toHexString(svcNumber),
                                "mov pc, lr"));
                        byte[] code = encoded.getMachineCode();
                        pointer.write(0, code, 0, code.length);
                        return null;
                    }
                }
                @Override
                public long handle(Emulator<?> emulator) {
                    if (callback != null) {
                        return callback.onHook(emulator);
                    }
                    return emulator.getBackend().reg_read(ArmConst.UC_ARM_REG_R0).intValue();
                }
            });
        } finally {
            if (capstone != null) {
                capstone.close();
            }
        }
    }

    private static byte[] readThumbCode(Pointer pointer) {
        short ins = pointer.getShort(0);
        if(ARM.isThumb32(ins)) { // thumb32
            return pointer.getByteArray(0, 4);
        } else {
            return pointer.getByteArray(0, 2);
        }
    }

    public static void simpleThumbIntercept(Emulator<?> emulator, long address, InterceptCallback callback) {
        Pointer pointer = UnidbgPointer.pointer(emulator, address);
        if (pointer == null) {
            throw new IllegalArgumentException();
        }
        Capstone capstone = null;
        try {
            capstone = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_THUMB);
            capstone.setDetail(Capstone.CS_OPT_ON);

            byte[] code = readThumbCode(pointer);
            Capstone.CsInsn[] insns = capstone.disasm(code, 0, 1);
            if (insns == null || insns.length < 1) {
                throw new IllegalArgumentException("Invalid intercept address: " + pointer);
            }
            Capstone.CsInsn insn = insns[0];
            emulator.getSvcMemory().registerSvc(new ThumbIntercept(pointer, callback, insn, code.length == 4));
        } finally {
            if (capstone != null) {
                capstone.close();
            }
        }
    }

    public static void simpleArmIntercept(Emulator<?> emulator, long address, InterceptCallback callback) {
        Pointer pointer = UnidbgPointer.pointer(emulator, address);
        if (pointer == null) {
            throw new IllegalArgumentException();
        }
        Capstone capstone = null;
        try {
            capstone = new Capstone(Capstone.CS_ARCH_ARM, Capstone.CS_MODE_ARM);
            capstone.setDetail(Capstone.CS_OPT_ON);

            byte[] code = pointer.getByteArray(0, 4);
            Capstone.CsInsn[] insns = capstone.disasm(code, 0, 1);
            if (insns == null || insns.length < 1) {
                throw new IllegalArgumentException("Invalid intercept address: " + pointer);
            }
            Capstone.CsInsn insn = insns[0];
            emulator.getSvcMemory().registerSvc(new ArmIntercept(pointer, callback, insn));
        } finally {
            if (capstone != null) {
                capstone.close();
            }
        }
    }

}
