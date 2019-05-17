package cn.banny.unidbg.linux.android.dvm;

public class IntArray extends DvmObject<int[]> implements Array<int[]> {

    IntArray(int[] value) {
        super(null, value);
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
