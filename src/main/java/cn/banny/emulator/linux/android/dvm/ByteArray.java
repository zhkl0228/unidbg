package cn.banny.emulator.linux.android.dvm;

import cn.banny.emulator.memory.MemoryBlock;

public class ByteArray extends DvmObject<byte[]> implements Array<byte[]> {

    public ByteArray(byte[] value) {
        super(null, value);
    }

    MemoryBlock memoryBlock;

    @Override
    public int length() {
        return value.length;
    }

    void setValue(byte[] value) {
        super.value = value;
    }

    @Override
    public void setData(int start, byte[] data) {
        System.arraycopy(data, 0, value, start, data.length);
    }
}
