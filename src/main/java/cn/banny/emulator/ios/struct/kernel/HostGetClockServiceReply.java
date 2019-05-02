package cn.banny.emulator.ios.struct.kernel;

import cn.banny.emulator.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class HostGetClockServiceReply extends UnicornStructure {

    public HostGetClockServiceReply(Pointer p) {
        super(p);
    }

    public MachMsgBody body;
    public MachMsgPortDescriptor clock_server;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("body", "clock_server");
    }

}
