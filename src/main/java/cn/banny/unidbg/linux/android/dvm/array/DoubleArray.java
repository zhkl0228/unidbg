package cn.banny.unidbg.linux.android.dvm.array;

import cn.banny.unidbg.linux.android.dvm.Array;

public class DoubleArray extends BaseArray<double[]> implements Array<double[]> {

    public DoubleArray(double[] value) {
        super(value);
    }

    @Override
    public int length() {
        return value.length;
    }

    @Override
    public void setData(int start, double[] data) {
        System.arraycopy(data, 0, value, start, data.length);
    }
}
