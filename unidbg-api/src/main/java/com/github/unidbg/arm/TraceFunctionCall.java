package com.github.unidbg.arm;

import capstone.api.Instruction;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.debugger.FunctionCallListener;
import com.github.unidbg.utils.Inspector;
import org.apache.commons.collections4.Bag;
import org.apache.commons.collections4.bag.HashBag;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Stack;

public abstract class TraceFunctionCall implements CodeHook {

    private static final Log log = LogFactory.getLog(TraceFunctionCall.class);

    protected final Emulator<?> emulator;
    private final FunctionCallListener listener;

    TraceFunctionCall(Emulator<?> emulator, FunctionCallListener listener) {
        this.emulator = emulator;
        this.listener = listener;
    }

    private static class FunctionCall {
        private final long callerAddress;
        private final long functionAddress;
        private final long returnAddress;
        private final Number[] args;
        public FunctionCall(long callerAddress, long functionAddress, long returnAddress, Number[] args) {
            this.callerAddress = callerAddress;
            this.functionAddress = functionAddress;
            this.returnAddress = returnAddress;
            this.args = args;
        }
    }

    private final Stack<FunctionCall> stack = new Stack<>();
    private final Bag<Long> bag = new HashBag<>();

    final void pushFunction(long callerAddress, long functionAddress, long returnAddress, Number[] args) {
        stack.push(new FunctionCall(callerAddress, functionAddress, returnAddress, args));
        bag.add(returnAddress);
        listener.onCall(emulator, callerAddress, functionAddress);
    }

    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        if (bag.remove(address)) {
            FunctionCall functionCall = stack.pop();
            if (functionCall.returnAddress != address) {
                throw new IllegalStateException();
            } else {
                listener.postCall(emulator, functionCall.callerAddress, functionCall.functionAddress, functionCall.args);
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
