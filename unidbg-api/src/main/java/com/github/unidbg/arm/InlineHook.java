package com.github.unidbg.arm;

import capstone.api.Disassembler;
import capstone.api.DisassemblerFactory;
import capstone.api.Instruction;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.hook.HookCallback;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.ArmConst;

import java.io.IOException;
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
        try (Disassembler disassembler = DisassemblerFactory.createArmDisassembler(true)) {
            disassembler.setDetail(true);

            byte[] code = readThumbCode(pointer);
            Instruction[] insns = disassembler.disasm(code, 0, 1);
            if (insns == null || insns.length < 1) {
                throw new IllegalArgumentException("Invalid hook address: " + pointer);
            }
            Instruction insn = insns[0];
            String asm = insn.toString();
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
        } catch (IOException e) {
            throw new IllegalStateException(e);
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
        try (Disassembler disassembler = DisassemblerFactory.createArmDisassembler(false)) {
            disassembler.setDetail(true);

            byte[] code = pointer.getByteArray(0, 4);
            Instruction[] insns = disassembler.disasm(code, 0, 1);
            if (insns == null || insns.length < 1) {
                throw new IllegalArgumentException("Invalid hook address: " + pointer);
            }
            Instruction insn = insns[0];
            String asm = insn.toString();
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
        } catch (IOException e) {
            throw new IllegalStateException(e);
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

}
