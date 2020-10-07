package com.github.unidbg.arm.context;

import com.github.unidbg.pointer.UnidbgPointer;

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

    UnidbgPointer getR0Pointer();

    UnidbgPointer getR1Pointer();

    UnidbgPointer getR2Pointer();

    UnidbgPointer getR3Pointer();

    UnidbgPointer getR4Pointer();

    UnidbgPointer getR5Pointer();

    UnidbgPointer getR6Pointer();

    UnidbgPointer getR7Pointer();

    UnidbgPointer getR8Pointer();

    UnidbgPointer getR9Pointer();

    UnidbgPointer getR10Pointer();

    UnidbgPointer getR11Pointer();

    UnidbgPointer getR12Pointer();

}
