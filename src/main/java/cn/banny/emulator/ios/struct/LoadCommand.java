package cn.banny.emulator.ios.struct;

import cn.banny.emulator.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class LoadCommand extends UnicornStructure {

    public LoadCommand(Pointer p) {
        super(p);
    }

    public int type;
    public int size;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("type", "size");
    }

}
