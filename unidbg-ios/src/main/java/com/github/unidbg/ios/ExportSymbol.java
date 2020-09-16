package com.github.unidbg.ios;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;

class ExportSymbol extends Symbol implements MachO {

    private final long address;
    private final MachOModule module;
    private final long other;
    private final int flags;

    ExportSymbol(String name, long address, Module module, long other, int flags) {
        super(name);
        this.address = address;
        this.module = (MachOModule) module;
        this.other = other;
        this.flags = flags;
    }

    public long getOtherWithBase() {
        return module.base + other;
    }

    @Override
    public Number[] call(Emulator<?> emulator, Object... args) {
        return module.callFunction(emulator, getValue(), args);
    }

    private boolean isAbsoluteSymbol() {
        return (flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE;
    }

    private boolean isRegularSymbol() {
        return (flags & EXPORT_SYMBOL_FLAGS_KIND_MASK) == EXPORT_SYMBOL_FLAGS_KIND_REGULAR;
    }

    @Override
    public long getAddress() {
        if (isAbsoluteSymbol()) {
            return address;
        } else if(isRegularSymbol()) {
            return module.machHeader + address;
        } else {
            throw new IllegalStateException("flags=0x" + Integer.toHexString(flags));
        }
    }

    @Override
    public long getValue() {
        if (isRegularSymbol()) {
            return address;
        } else {
            throw new UnsupportedOperationException("flags=0x" + Integer.toHexString(flags));
        }
    }

    @Override
    public boolean isUndef() {
        return false;
    }

    @Override
    public String getModuleName() {
        return module.name;
    }
}
