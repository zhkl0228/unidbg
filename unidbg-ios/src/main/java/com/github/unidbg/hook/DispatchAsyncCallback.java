package com.github.unidbg.hook;

import com.sun.jna.Pointer;

public interface DispatchAsyncCallback {

    boolean canDispatch(Pointer dq, Pointer fun);

}
