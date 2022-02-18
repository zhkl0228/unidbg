package com.github.unidbg.ios.struct.cf;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public final class CFString extends UnidbgStructure {

    public CFString(Pointer p) {
        super(p);
        unpack();
    }

    public long isa; // ptr
    public long info; // ptr
    public long data; // ptr
    public int length;

    public String getData(Emulator<?> emulator) {
        Pointer ptr = UnidbgPointer.pointer(emulator, data);
        byte[] data = Objects.requireNonNull(ptr).getByteArray(0, length);
        return new String(data, StandardCharsets.UTF_8);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("isa", "info", "data", "length");
    }

}
