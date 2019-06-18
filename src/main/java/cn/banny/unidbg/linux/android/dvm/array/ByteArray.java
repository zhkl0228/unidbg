package cn.banny.unidbg.linux.android.dvm.array;

import cn.banny.unidbg.linux.android.dvm.Array;

public class ByteArray extends BaseArray<byte[]> implements Array<byte[]> {

    public ByteArray(byte[] value) {
        super(value);
    }

    @Override
    public int length() {
        return value.length;
    }

    public void setValue(byte[] value) {
        super.value = value;
    }

    @Override
    public void setData(int start, byte[] data) {
        System.arraycopy(data, 0, value, start, data.length);
    }
}
