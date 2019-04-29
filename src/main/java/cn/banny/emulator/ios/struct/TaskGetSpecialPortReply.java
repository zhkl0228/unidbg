package cn.banny.emulator.ios.struct;

import cn.banny.emulator.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class TaskGetSpecialPortReply extends UnicornStructure {

    public TaskGetSpecialPortReply(Pointer p) {
        super(p);
    }

    public MachMsgBody body;
    public MachMsgPortDescriptor specialPort;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("body", "specialPort");
    }

}
