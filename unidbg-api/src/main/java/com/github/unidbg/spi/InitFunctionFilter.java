package com.github.unidbg.spi;

import com.github.unidbg.Emulator;

public interface InitFunctionFilter {

    boolean accept(Emulator<?> emulator, long address);

}
