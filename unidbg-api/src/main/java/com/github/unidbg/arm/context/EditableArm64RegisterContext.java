package com.github.unidbg.arm.context;

import com.sun.jna.Pointer;

public interface EditableArm64RegisterContext extends Arm64RegisterContext {

    void setXLong(int index, long value);

    void setStackPointer(Pointer sp);

}
