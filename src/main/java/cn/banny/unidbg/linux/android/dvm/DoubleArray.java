package cn.banny.unidbg.linux.android.dvm;

import cn.banny.unidbg.memory.MemoryBlock;

public class DoubleArray extends DvmObject<double[]> implements Array<double[]> {

    public DoubleArray(double[] value) {
        super(null, value);
    }

    MemoryBlock memoryBlock;

    @Override
    public int length() {
        return value.length;
    }

    void setValue(double[] value) {
        super.value = value;
    }

    @Override
    public void setData(int start, double[] data) {
        System.arraycopy(data, 0, value, start, data.length);
    }
}