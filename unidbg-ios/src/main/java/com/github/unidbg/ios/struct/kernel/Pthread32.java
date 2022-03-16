package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Pthread32 extends Pthread {

    public Pthread32(Emulator<?> emulator, byte[] data) {
        super(emulator, data);
        setAlignType(ALIGN_NONE);
    }

    public Pthread32(Pointer p) {
        super(p);
        setAlignType(ALIGN_NONE);
    }

    @Override
    public void setThreadId(int threadId) {
        this.thread_id = threadId;
    }

    @Override
    public int getThreadId() {
        return (int) thread_id;
    }

    @Override
    public void setDetached(int detached) {
        this.detached |= PTHREAD_CREATE_JOINABLE;
    }

    @Override
    public void setExitValue(int value) {
        this.exit_value = value;
    }

    public int sig; // _PTHREAD_SIG
    public int __cleanup_stack;
    public int childrun;
    public int lock;
    public int detached;
    public long thread_id; // 64-bit unique thread id
    public int pad0;
    public int fun; // thread start routine
    public int arg; // thread start routine argument
    public int exit_value; // thread exit value storage
    public int joiner_notify; // pthread_join notification
    public int max_tsd_key;
    public int cancel_state; // whether the thread can be cancelled
    public int cancel_error;
    public int err_no; // thread-local errno
    public int joiner;
    public int sched_priority;
    public TailqPthread32 plist; // global thread list

    public int stackaddr; // base of the stack
    public int stacksize; // size of stack (page multiple and >= PTHREAD_STACK_MIN)

    @Override
    public void setStack(Pointer stackAddress, long stackSize) {
        this.stackaddr = (int) UnidbgPointer.nativeValue(stackAddress);
        this.stacksize = (int) stackSize;
    }

    @Override
    public void setSig(long sig) {
        this.sig = (int) sig;
    }

    public int freeaddr; // stack/thread allocation base address
    public int freesize; // stack/thread allocation size
    public int guardsize; // guard page size in bytes

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("sig", "__cleanup_stack", "childrun", "lock", "detached", "thread_id", "fun", "arg",
                "exit_value", "joiner_notify", "max_tsd_key", "cancel_state", "cancel_error", "err_no", "joiner",
                "sched_priority", "plist", "pad0", "pthread_name", "stackaddr", "stacksize", "freeaddr", "freesize", "guardsize",
                "self", "errno", "mig_reply", "machThreadSelf");
    }

    // thread specific data
    public int self;
    public int errno;
    public int mig_reply;
    public int machThreadSelf;

    @Override
    public void setSelf(Pointer self) {
        this.self = (int) UnidbgPointer.nativeValue(self);
    }

    @Override
    public void setMachThreadSelf(long machThreadSelf) {
        this.machThreadSelf = (int) machThreadSelf;
    }

    @Override
    public Pointer getErrnoPointer(Emulator<?> emulator) {
        return UnidbgPointer.pointer(emulator, errno);
    }
}
