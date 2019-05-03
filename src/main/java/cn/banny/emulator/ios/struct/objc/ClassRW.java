package cn.banny.emulator.ios.struct.objc;

import cn.banny.emulator.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class ClassRW extends UnicornStructure implements Objc {

    public ClassRW(Pointer p) {
        super(p);
    }

    public int flags;
    public int version;
    public Pointer ro;
    public Pointer methodList;
    public Pointer properties;
    public Pointer protocols;

    public Pointer firstSubclass;
    public Pointer nextSiblingClass;

    public Pointer demangledName;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("flags", "version", "ro", "methodList", "properties", "protocols", "firstSubclass", "nextSiblingClass", "demangledName");
    }

    public boolean isRealized() {
        return (flags & RW_REALIZED) != 0;
    }

    public void changeFlags(int set, int clear) {
        flags = (flags | set) & ~clear;
    }

}
