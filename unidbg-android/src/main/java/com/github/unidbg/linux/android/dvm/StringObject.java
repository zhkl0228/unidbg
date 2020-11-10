package com.github.unidbg.linux.android.dvm;

public class StringObject extends DvmObject<String> {

    public StringObject(VM vm, String value) {
        super(vm.resolveClass("java/lang/String"), value);

        if (value == null) {
            throw new NullPointerException();
        }
    }

    @Override
    public String toString() {
        if (value == null) {
            return null;
        } else {
            return '"' + value + '"';
        }
    }
}
