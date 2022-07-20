package com.github.unidbg.ios.objc;

import com.github.unidbg.Symbol;
import com.github.unidbg.ios.MachOModule;

public interface ObjectiveCProcessor {

    Symbol findObjcSymbol(Symbol bestSymbol, long targetAddress, MachOModule module);

}
