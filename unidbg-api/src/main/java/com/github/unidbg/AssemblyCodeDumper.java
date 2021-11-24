package com.github.unidbg;

import capstone.Arm64_const;
import capstone.Arm_const;
import capstone.api.Instruction;
import capstone.api.RegsAccess;
import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.arm.InstructionVisitor;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.listener.TraceCodeListener;

import java.io.PrintStream;
import java.util.Arrays;

/**
 * my code hook
 * Created by zhkl0228 on 2017/5/2.
 */

public class AssemblyCodeDumper implements CodeHook, TraceHook {

    private final Emulator<?> emulator;

    public AssemblyCodeDumper(Emulator<?> emulator) {
        super();

        this.emulator = emulator;
    }

    private boolean traceInstruction;
    private long traceBegin, traceEnd;
    private TraceCodeListener listener;

    public void initialize(long begin, long end, TraceCodeListener listener) {
        this.traceInstruction = true;
        this.traceBegin = begin;
        this.traceEnd = end;
        this.listener = listener;
    }

    private UnHook unHook;

    @Override
    public void onAttach(UnHook unHook) {
        if (this.unHook != null) {
            throw new IllegalStateException();
        }
        this.unHook = unHook;
    }

    @Override
    public void detach() {
        if (unHook != null) {
            unHook.unhook();
            unHook = null;
        }
    }

    @Override
    public void stopTrace() {
        detach();
        IOUtils.close(redirect);
        redirect = null;
    }

    private boolean canTrace(long address) {
        return traceInstruction && (traceBegin > traceEnd || (address >= traceBegin && address <= traceEnd));
    }

    private PrintStream redirect;

    @Override
    public void setRedirect(PrintStream redirect) {
        this.redirect = redirect;
    }

    @Override
    public void hook(final Backend backend, long address, int size, Object user) {
        if (canTrace(address)) {
            try {
                PrintStream out = System.out;
                if (redirect != null) {
                    out = redirect;
                }
                Instruction[] insns = emulator.printAssemble(out, address, size, new InstructionVisitor() {
                    @Override
                    public void visit(StringBuilder builder, Instruction ins) {
                        RegsAccess regsAccess = ins.regsAccess();
                        if (regsAccess == null) {
                            return;
                        }
                        short[] regsRead = regsAccess.getRegsRead();
                        for (short reg : regsRead) {
                            if (emulator.is32Bit()) {
                                if ((reg >= Arm_const.ARM_REG_R0 && reg <= Arm_const.ARM_REG_R12) ||
                                        reg == Arm_const.ARM_REG_LR || reg == Arm_const.ARM_REG_SP) {
                                    int value = backend.reg_read(reg).intValue();
                                    builder.append(' ').append(ins.regName(reg)).append("=0x").append(Long.toHexString(value & 0xffffffffL));
                                }
                            } else {
                                if ((reg >= Arm64_const.ARM64_REG_X0 && reg <= Arm64_const.ARM64_REG_X28) ||
                                        (reg >= Arm64_const.ARM64_REG_X29 && reg <= Arm64_const.ARM64_REG_SP)) {
                                    long value = backend.reg_read(reg).longValue();
                                    builder.append(' ').append(ins.regName(reg)).append("=0x").append(Long.toHexString(value));
                                } else if (reg >= Arm64_const.ARM64_REG_W0 && reg <= Arm64_const.ARM64_REG_W30) {
                                    int value = backend.reg_read(reg).intValue();
                                    builder.append(' ').append(ins.regName(reg)).append("=0x").append(Long.toHexString(value & 0xffffffffL));
                                }
                            }
                        }
                    }
                });
                if (listener != null) {
                    if (insns == null || insns.length != 1) {
                        throw new IllegalStateException("insns=" + Arrays.toString(insns));
                    }
                    listener.onInstruction(emulator, address, insns[0]);
                }
            } catch (BackendException e) {
                throw new IllegalStateException(e);
            }
        }
    }

}
