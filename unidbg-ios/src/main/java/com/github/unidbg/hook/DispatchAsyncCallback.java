package com.github.unidbg.hook;

import com.github.unidbg.Emulator;
import com.sun.jna.Pointer;

public interface DispatchAsyncCallback {

    boolean canDispatch(Emulator<?> emulator, Pointer dq, Pointer fun, boolean is_barrier_async);

}
