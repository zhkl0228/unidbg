package cn.banny.unidbg.arm.context;

public interface EditableArm64RegisterContext extends Arm64RegisterContext {

    void setXLong(int index, long value);

}
