package cn.banny.unidbg.ios.struct.kernel;

import cn.banny.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Collections;
import java.util.List;

public class MachPortLimits extends UnicornStructure {

    public MachPortLimits(Pointer p) {
        super(p);
    }

    public int mpl_qlimit; /* number of msgs */

    @Override
    protected List<String> getFieldOrder() {
        return Collections.singletonList("mpl_qlimit");
    }
}
