package cn.banny.emulator.ios.struct;

import cn.banny.emulator.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class SemaphoreCreateRequest extends UnicornStructure {

    public SemaphoreCreateRequest(Pointer p) {
        super(p);
    }

    public NDR_record NDR;
    public int policy;
    public int value;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("NDR", "policy", "value");
    }

}
