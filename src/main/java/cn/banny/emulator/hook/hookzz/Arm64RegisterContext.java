package cn.banny.emulator.hook.hookzz;

import com.sun.jna.Pointer;

public interface Arm64RegisterContext extends RegisterContext {

    long getX(int index);

    Pointer getXPointer(int index);

    long getFp();

    Pointer getFpPointer();

}
