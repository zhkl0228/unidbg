package cn.banny.emulator.ios.struct.kernel;

import cn.banny.emulator.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class HostGetClockServiceRequest extends UnicornStructure {

    public HostGetClockServiceRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int clock_id;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "clock_id");
    }

}
