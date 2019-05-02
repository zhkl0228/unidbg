package cn.banny.emulator.ios.struct.kernel;

import cn.banny.emulator.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Collections;
import java.util.List;

public class MachMsgBody extends UnicornStructure {

    public MachMsgBody(Pointer p) {
        super(p);
    }

    public int msgh_descriptor_count;

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("msgh_descriptor_count");
    }
}
