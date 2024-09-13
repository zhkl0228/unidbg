package com.github.unidbg.arm;

import capstone.api.Instruction;
import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.debugger.FunctionCallListener;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.thread.BaseTask;
import com.github.unidbg.thread.RunnableTask;
import com.github.unidbg.utils.Inspector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class TraceFunctionCall implements CodeHook {

    private static final Logger log = LoggerFactory.getLogger(TraceFunctionCall.class);

    protected final Emulator<?> emulator;
    private final FunctionCallListener listener;

    TraceFunctionCall(Emulator<?> emulator, FunctionCallListener listener) {
        this.emulator = emulator;
        this.listener = listener;
    }

    final void pushFunction(long callerAddress, long functionAddress, long returnAddress, Number[] args) {
        RunnableTask runningTask = emulator.getThreadDispatcher().getRunningTask();
        FunctionCall call = new FunctionCall(callerAddress, functionAddress, returnAddress, args);
        runningTask.pushFunction(emulator, call);
        listener.onDebugPushFunction(emulator, call);
        listener.onCall(emulator, callerAddress, functionAddress);
    }

    private boolean detectedIllegalState;

    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        if (detectedIllegalState) {
            return;
        }

        RunnableTask runningTask = emulator.getThreadDispatcher().getRunningTask();
        FunctionCall call = runningTask.popFunction(emulator, address);
        if (call != null) {
            listener.onDebugPopFunction(emulator, address, call);
            if (call.returnAddress != address) {
                log.warn("Illegal state address={}, call={}", UnidbgPointer.pointer(emulator, address), call.toReadableString(emulator));
                if (LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled() ||
                        LoggerFactory.getLogger(BaseTask.class).isDebugEnabled()) {
                    emulator.attach().debug();
                }
                detectedIllegalState = true;
                return;
            } else {
                listener.postCall(emulator, call.callerAddress, call.functionAddress, call.args);
            }
        }
        try {
            Instruction instruction = disassemble(address, size);
            if (instruction != null) {
                if (log.isDebugEnabled()) {
                    if (!instruction.getMnemonic().startsWith("bl")) {
                        log.warn(Inspector.inspectString(backend.mem_read(address, size), "Invalid " + instruction + ": thumb=" + ARM.isThumb(backend)));
                    }
                }
                onInstruction(instruction);
            } else if (log.isDebugEnabled()) {
                Instruction[] instructions = emulator.disassemble(address, size, 1);
                if (instructions.length != 1) {
                    return;
                }
                instruction = instructions[0];
                String mnemonic = instruction.getMnemonic();
                if (emulator.is32Bit()) {
                    if (mnemonic.startsWith("bl") &&
                            !mnemonic.startsWith("ble") &&
                            !mnemonic.startsWith("blt") &&
                            !mnemonic.startsWith("bls") &&
                            !mnemonic.startsWith("blo")) {
                        log.warn(Inspector.inspectString(backend.mem_read(address, size), "Unsupported " + instruction + ": thumb=" + ARM.isThumb(backend)));
                    }
                } else {
                    if (mnemonic.startsWith("bl")) {
                        log.warn(Inspector.inspectString(backend.mem_read(address, size), "Unsupported " + instruction + ": thumb=" + ARM.isThumb(backend)));
                    }
                }
            }
        } catch (BackendException e) {
            throw new IllegalStateException(e);
        }
    }

    protected abstract Instruction disassemble(long address, int size);

    protected abstract void onInstruction(Instruction instruction);

    private UnHook unHook;

    @Override
    public void onAttach(UnHook unHook) {
        this.unHook = unHook;
    }

    @Override
    public void detach() {
        if (unHook != null) {
            unHook.unhook();
            unHook = null;
        }
    }

}
