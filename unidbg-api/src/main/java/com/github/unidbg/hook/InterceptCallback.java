package com.github.unidbg.hook;

import com.github.unidbg.Emulator;

public interface InterceptCallback {

    void onIntercept(Emulator<?> emulator);

}
