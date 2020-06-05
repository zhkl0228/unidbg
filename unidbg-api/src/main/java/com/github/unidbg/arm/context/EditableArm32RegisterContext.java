package com.github.unidbg.arm.context;

import com.sun.jna.Pointer;

public interface EditableArm32RegisterContext extends Arm32RegisterContext {

    void setR0(int r0);

    void setR1(int r1);

    void setR2(int r2);

    void setR3(int r3);

    void setR4(int r4);

    void setR5(int r5);

    void setR6(int r6);

    void setR7(int r7);

    void setStackPointer(Pointer sp);

}
