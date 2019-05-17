package cn.banny.unidbg.hook.hookzz;

import cn.banny.unidbg.pointer.UnicornPointer;

public interface Arm32RegisterContext extends RegisterContext {

    long getR0();

    long getR1();

    long getR2();

    long getR3();

    long getR4();

    long getR5();

    long getR6();

    long getR7();

    long getR8();

    long getR9();

    long getR10();

    long getR11();

    long getR12();

    UnicornPointer getR0Pointer();

    UnicornPointer getR1Pointer();

    UnicornPointer getR2Pointer();

    UnicornPointer getR3Pointer();

    UnicornPointer getR4Pointer();

    UnicornPointer getR5Pointer();

    UnicornPointer getR6Pointer();

    UnicornPointer getR7Pointer();

    UnicornPointer getR8Pointer();

    UnicornPointer getR9Pointer();

    UnicornPointer getR10Pointer();

    UnicornPointer getR11Pointer();

    UnicornPointer getR12Pointer();

}
