package cn.banny.emulator.linux.android.dvm;

public class ArrayObject extends DvmObject<DvmObject[]> implements Array<DvmObject[]> {

    public ArrayObject(DvmObject...value) {
        super(null, value);
    }

    @Override
    public int length() {
        return value.length;
    }

    @Override
    public void setData(int start, DvmObject[] data) {
        System.arraycopy(data, 0, value, start, data.length);
    }
}
