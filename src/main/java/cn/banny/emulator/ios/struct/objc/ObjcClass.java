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

    public Pointer metaClass;
    public Pointer superClass;
    public Pointer cache;
    public Pointer vtable;
    public Pointer data;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("metaClass", "superClass", "cache", "vtable", "data");
    }

    public void setData(ClassRW classRW) {
        data = classRW.getPointer();
    }

}
