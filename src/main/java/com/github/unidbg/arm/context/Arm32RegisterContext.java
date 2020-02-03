package com.github.unidbg.arm.context;

import com.github.unidbg.pointer.UnicornPointer;

public interface Arm32RegisterContext extends RegisterContext {

    long getR0Long();

    long getR1Long();

    long getR2Long();

    long getR3Long();

    long getR4Long();

    long getR5Long();

    long getR6Long();

    long getR7Long();

    long getR8Long();

    long getR9Long();

    long getR10Long();

    long getR11Long();

    long getR12Long();

    int getR0Int();

    int getR1Int();

    int getR2Int();

    int getR3Int();

    int getR4Int();

    int getR5Int();

    int getR6Int();

    int getR7Int();

    int getR8Int();

    int getR9Int();

    int getR10Int();

    int getR11Int();

    int getR12Int();

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
