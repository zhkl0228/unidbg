package com.github.unidbg;

import capstone.Capstone;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.listener.TraceCodeListener;
import org.apache.commons.io.IOUtils;
import unicorn.Unicorn;

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

    private Unicorn.UnHook unHook;

    @Override
    public void onAttach(Unicorn.UnHook unHook) {
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
        IOUtils.closeQuietly(redirect);
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
    public void hook(Backend backend, long address, int size, Object user) {
        if (canTrace(address)) {
            try {
                PrintStream out = System.out;
                if (redirect != null) {
                    out = redirect;
                }
                Capstone.CsInsn[] insns = emulator.printAssemble(out, address, size);
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
