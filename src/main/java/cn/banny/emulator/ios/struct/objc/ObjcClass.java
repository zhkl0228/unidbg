package cn.banny.emulator.ios.struct.objc;

import cn.banny.emulator.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

/**
 * objc_class
 */
public class ObjcClass extends UnicornStructure {

    public ObjcClass(Pointer p) {
        super(p);
    }

    public int metaClass;
    public int superClass;
    public int cache;
    public int vtable;
    public int data;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("metaClass", "superClass", "cache", "vtable", "data");
    }

}
