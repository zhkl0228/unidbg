package cn.banny.emulator.hook.hookzz;

import com.sun.jna.Pointer;

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

    Pointer getR0Pointer();

    Pointer getR1Pointer();

    Pointer getR2Pointer();

    Pointer getR3Pointer();

    Pointer getR4Pointer();

    Pointer getR5Pointer();

    Pointer getR6Pointer();

    Pointer getR7Pointer();

    Pointer getR8Pointer();

    Pointer getR9Pointer();

    Pointer getR10Pointer();

    Pointer getR11Pointer();

    Pointer getR12Pointer();

}
