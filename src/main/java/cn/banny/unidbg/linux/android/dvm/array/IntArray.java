package cn.banny.unidbg.linux.android.dvm.array;

import cn.banny.unidbg.linux.android.dvm.Array;

public class IntArray extends BaseArray<int[]> implements Array<int[]> {

    public IntArray(int[] value) {
        super(value);
    }

    @Override
    public int length() {
        return value.length;
    }

    @Override
    public void setData(int start, int[] data) {
        System.arraycopy(data, 0, value, start, data.length);
    }
}
