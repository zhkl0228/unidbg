package com.github.unidbg.ios.struct.kernel;

import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Pthread64 extends Pthread {

    public Pthread64(Pointer p) {
        super(p);
    }

    public long sig; // _PTHREAD_SIG
    public Pointer __cleanup_stack;
    public int childrun;
    public int lock;
    public int detached;
    public int pad0;
    public long thread_id; // 64-bit unique thread id
    public Pointer fun; // thread start routine
    public Pointer arg; // thread start routine argument
    public Pointer exit_value; // thread exit value storage
    public Pointer joiner_notify; // pthread_join notification
    public int max_tsd_key;
    public int cancel_state; // whether the thread can be cancelled
    public int cancel_error;
    public int err_no; // thread-local errno
    public Pointer joiner;
    public SchedParam param;
    public TailqPthread plist; // global thread list

    public Pointer stackaddr; // base of the stack
    public long stacksize; // size of stack (page multiple and >= PTHREAD_STACK_MIN)

    public Pointer freeaddr; // stack/thread allocation base address
    public long freesize; // stack/thread allocation size
    public long guardsize; // guard page size in bytes

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("sig", "__cleanup_stack", "childrun", "lock", "detached", "pad0", "thread_id", "fun", "arg",
                "exit_value", "joiner_notify", "max_tsd_key", "cancel_state", "cancel_error", "err_no", "joiner",
                "param", "plist", "pthread_name", "stackaddr", "stacksize", "freeaddr", "freesize", "guardsize",
                "self", "errno", "mig_reply", "machThreadSelf");
    }
}
