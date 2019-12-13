package cn.banny.unidbg.linux.android.dvm;

public interface VaList {

    <T extends DvmObject<?>> T getObject(int offset);

    int getInt(int offset);

    long getLong(int offset);

}
