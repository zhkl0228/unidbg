package com.github.unidbg.thread;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.FunctionCall;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.commons.collections4.Bag;
import org.apache.commons.collections4.bag.HashBag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.util.Stack;

public abstract class BaseTask implements RunnableTask {

    private static final Logger log = LoggerFactory.getLogger(BaseTask.class);

    private Waiter waiter;
    private int stackSpaceAllocIndex = -1;

    @Override
    public void setWaiter(Emulator<?> emulator, Waiter waiter) {
        this.waiter = waiter;

        if (waiter != null &&
                log.isTraceEnabled()) {
            emulator.attach().debug();
        }
    }

    @Override
    public Waiter getWaiter() {
        return waiter;
    }

    @Override
    public final boolean canDispatch() {
        if (waiter != null) {
            return waiter.canDispatch();
        }
        return true;
    }

    private long context;

    @Override
    public final boolean isContextSaved() {
        return this.context != 0;
    }

    @Override
    public final void saveContext(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        if (this.context == 0) {
            this.context = backend.context_alloc();
        }
        backend.context_save(this.context);
    }

    @Override
    public void popContext(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        int off = emulator.popContext();
        long pc;
        if (emulator.is32Bit()) {
            pc = backend.reg_read(ArmConst.UC_ARM_REG_PC).intValue() & 0xfffffffeL;
        } else {
            pc = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
        }
        backend.reg_write(emulator.is32Bit() ? ArmConst.UC_ARM_REG_PC : Arm64Const.UC_ARM64_REG_PC, pc + off);
        saveContext(emulator);
    }

    @Override
    public void restoreContext(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        backend.context_restore(this.context);
    }

    protected final Number continueRun(AbstractEmulator<?> emulator, long until) {
        Backend backend = emulator.getBackend();
        backend.context_restore(this.context);
        long pc;
        if (emulator.is32Bit()) {
            pc = backend.reg_read(ArmConst.UC_ARM_REG_PC).intValue() & 0xfffffffeL;
            if (ARM.isThumb(backend)) {
                pc |= 1;
            }
        } else {
            pc = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
        }
        if (log.isDebugEnabled()) {
            log.debug("continue run task={}, pc={}, until=0x{}", this, UnidbgPointer.pointer(emulator, pc), Long.toHexString(until));
        }
        Waiter waiter = getWaiter();
        if (waiter != null) {
            waiter.onContinueRun(emulator);
            setWaiter(emulator, null);
        }
        return emulator.emulate(pc, until);
    }

    @Override
    public void destroy(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();

        if (stackSpaceAllocIndex != -1) {
            emulator.getMemory().freeThreadIndex(stackSpaceAllocIndex);
        }

        if (this.context != 0) {
            backend.context_free(this.context);
            this.context = 0;
        }

        if (destroyListener != null) {
            destroyListener.onDestroy(emulator);
        }
    }

    public static final int THREAD_STACK_PAGE = 64;

    protected final UnidbgPointer allocateStack(Emulator<?> emulator) {
        //stackBlock地址基于MMAP_BASE，必须想办法让它基于STACK_BASE(KVM在使用sp寄存器时会校验，校验失败直接升天）。
        if (stackSpaceAllocIndex == -1){
            stackSpaceAllocIndex = emulator.getMemory().allocateThreadIndex();
        }
        return emulator.getMemory().allocateThreadStack(stackSpaceAllocIndex);
    }

    @Override
    public void setResult(Emulator<?> emulator, Number ret) {
    }

    private DestroyListener destroyListener;

    @Override
    public void setDestroyListener(DestroyListener listener) {
        this.destroyListener = listener;
    }

    private final Stack<FunctionCall> stack = new Stack<>();
    private final Bag<Long> bag = new HashBag<>();

    @Override
    public void pushFunction(Emulator<?> emulator, FunctionCall call) {
        stack.push(call);
        bag.add(call.returnAddress, 1);

        if (log.isDebugEnabled()) {
            log.debug("pushFunction call={}, bagCount={}", call.toReadableString(emulator), bag.getCount(call.returnAddress));
        }
    }

    @Override
    public FunctionCall popFunction(Emulator<?> emulator, long address) {
        if (!bag.contains(address)) {
            return null;
        }

        FunctionCall call;
        if (emulator.is64Bit()) { // check LR for aarch64
            call = stack.peek();
            long lr = emulator.getContext().getLR();
            if (lr != call.returnAddress) {
                return null;
            }

            bag.remove(address, 1);
            stack.pop();
        } else {
            bag.remove(address, 1);
            call = stack.pop();
        }

        if (log.isDebugEnabled()) {
            log.debug("popFunction call={}, address={}, stackSize={}, bagCount={}", call.toReadableString(emulator), UnidbgPointer.pointer(emulator, address), stack.size(), bag.getCount(address));
        }
        if (call.returnAddress != address) {
            for (FunctionCall fc : stack) {
                log.warn("stackCall call={}, bagCount={}", fc.toReadableString(emulator), bag.getCount(fc.returnAddress));
            }
        }
        return call;
    }

    @Override
    public final String toString() {
        return getStatus() + "|" + toThreadString();
    }

    protected abstract String getStatus();
    protected abstract String toThreadString();

}
