package com.github.unidbg.hook;

import com.github.unidbg.Emulator;
import com.sun.jna.Pointer;

public interface DispatchAsyncCallback {

    enum Result {
        skip, thread_run, direct_run
    }

    Result canDispatch(Emulator<?> emulator, Pointer dq, Pointer fun, boolean is_barrier_async);

}
