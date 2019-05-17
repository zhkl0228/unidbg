package cn.banny.unidbg.hook.hookzz;

import cn.banny.unidbg.pointer.UnicornPointer;

public interface Arm64RegisterContext extends RegisterContext {

    long getX(int index);

    UnicornPointer getXPointer(int index);

    long getFp();

    UnicornPointer getFpPointer();

}
