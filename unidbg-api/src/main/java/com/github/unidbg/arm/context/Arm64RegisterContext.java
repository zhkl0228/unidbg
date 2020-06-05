package com.github.unidbg.arm.context;

import com.github.unidbg.pointer.UnicornPointer;

public interface Arm64RegisterContext extends RegisterContext {

    long getXLong(int index);

    int getXInt(int index);

    UnicornPointer getXPointer(int index);

    long getFp();

    UnicornPointer getFpPointer();

}
