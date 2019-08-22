package cn.banny.unidbg.linux.android.dvm;

import java.io.ByteArrayInputStream;

public class ByteArrayInputStreamObject  extends DvmObject<ByteArrayInputStream> {
    public ByteArrayInputStreamObject(VM vm, ByteArrayInputStream value) {
//        ByteArrayInputStream bis = new ByteArrayInputStream(value);
        super(vm.resolveClass("java/io/ByteArrayInputStream"), value);

        if (value == null) {
            throw new NullPointerException();
        }
    }
}
