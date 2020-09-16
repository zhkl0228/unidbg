package com.github.unidbg.memory;

import com.github.unidbg.Svc;
import com.github.unidbg.pointer.UnicornPointer;

public interface SvcMemory extends StackMemory {

    UnicornPointer allocate(int size, String label);

    UnicornPointer registerSvc(Svc svc);

    Svc getSvc(int svcNumber);

    MemRegion findRegion(long addr);

    long getBase();
    int getSize();

}
