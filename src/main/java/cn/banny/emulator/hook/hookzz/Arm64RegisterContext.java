package cn.banny.emulator.hook.hookzz;

import cn.banny.emulator.pointer.UnicornPointer;

public interface Arm64RegisterContext extends RegisterContext {

    long getX(int index);

    UnicornPointer getXPointer(int index);

    long getFp();

    UnicornPointer getFpPointer();

}
