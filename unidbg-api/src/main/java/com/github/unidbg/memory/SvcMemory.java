package com.github.unidbg.memory;

import com.github.unidbg.Svc;
import com.github.unidbg.pointer.UnidbgPointer;

public interface SvcMemory extends StackMemory {

    UnidbgPointer allocate(int size, String label);

    UnidbgPointer registerSvc(Svc svc);

    Svc getSvc(int svcNumber);

    MemRegion findRegion(long addr);

    long getBase();
    int getSize();

}
