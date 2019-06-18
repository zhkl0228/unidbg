package cn.banny.unidbg.linux.android.dvm.array;

import cn.banny.unidbg.linux.android.dvm.Array;

public class FloatArray extends BaseArray<float[]> implements Array<float[]> {

    public FloatArray(float[] value) {
        super(value);
    }

    @Override
    public int length() {
        return value.length;
    }

    public void setValue(float[] value) {
        super.value = value;
    }

    @Override
    public void setData(int start, float[] data) {
        System.arraycopy(data, 0, value, start, data.length);
    }

}
