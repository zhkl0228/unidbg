package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Pthread64 extends Pthread {

    public Pthread64(Pointer p) {
        super(p);
    }

    @Override
    public void setThreadId(int threadId) {
        this.thread_id = threadId;
    }

    @Override
    public int getThreadId() {
        return (int) thread_id;
    }

    public long sig; // _PTHREAD_SIG
    public long __cleanup_stack;
    public int childrun;
    public int lock;
    public int detached;
    public int pad0;
    public long thread_id; // 64-bit unique thread id
    public long fun; // thread start routine
    public long arg; // thread start routine argument
    public long exit_value; // thread exit value storage
    public long joiner_notify; // pthread_join notification
    public int max_tsd_key;
    public int cancel_state; // whether the thread can be cancelled
    public int cancel_error;
    public int err_no; // thread-local errno
    public long joiner;
    public SchedParam param;
    public TailqPthread64 plist; // global thread list

    public long stackaddr; // base of the stack
    public long stacksize; // size of stack (page multiple and >= PTHREAD_STACK_MIN)

    @Override
    public void setStack(Pointer stackAddress, long stackSize) {
        this.stackaddr = UnidbgPointer.nativeValue(stackAddress);
        this.stacksize = stackSize;
    }

    public long freeaddr; // stack/thread allocation base address
    public long freesize; // stack/thread allocation size
    public long guardsize; // guard page size in bytes

    @Override
    public void setSig(long sig) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setDetached(int detached) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setExitValue(int value) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("sig", "__cleanup_stack", "childrun", "lock", "detached", "pad0", "thread_id", "fun", "arg",
                "exit_value", "joiner_notify", "max_tsd_key", "cancel_state", "cancel_error", "err_no", "joiner",
                "param", "plist", "pthread_name", "stackaddr", "stacksize", "freeaddr", "freesize", "guardsize",
                "self", "errno", "mig_reply", "machThreadSelf");
    }

    // thread specific data
    public long self;
    public long errno;
    public long mig_reply;
    public long machThreadSelf;

    @Override
    public void setSelf(Pointer self) {
        this.self = UnidbgPointer.nativeValue(self);
    }

    @Override
    public void setMachThreadSelf(long machThreadSelf) {
        this.machThreadSelf = machThreadSelf;
    }

    @Override
    public Pointer getErrnoPointer(Emulator<?> emulator) {
        return UnidbgPointer.pointer(emulator, errno);
    }
}
