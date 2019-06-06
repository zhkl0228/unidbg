package cn.banny.unidbg.linux.android.dvm;

public class DoubleArray extends DvmObject<double[]> implements Array<double[]> {

    public DoubleArray(double[] value) {
        super(null, value);
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
