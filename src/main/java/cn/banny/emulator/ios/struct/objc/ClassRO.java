package cn.banny.emulator.ios.struct.objc;

import cn.banny.emulator.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

/**
 * class_ro_t
 */
public class ClassRO extends UnicornStructure {

    public ClassRO(Pointer p) {
        super(p);
    }

    public int flags;
    public int instanceStart;
    public int instanceSize;
    public int ivarLayout;
    public int name;
    public int baseMethods;
    public int baseProtocols;
    public int ivars;
    public int weakIvarLayout;
    public int baseProperties;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("flags", "instanceStart", "instanceSize", "ivarLayout", "name", "baseMethods", "baseProtocols", "ivars", "weakIvarLayout", "baseProperties");
    }
}
