package cn.banny.emulator.pointer;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

public abstract class UnicornStructure extends Structure {

    public UnicornStructure(Pointer p) {
        super(p);

        checkPointer(p);
    }

    private void checkPointer(Pointer p) {
        if (p == null) {
            throw new NullPointerException("p is null");
        }
        if (!(p instanceof UnicornPointer) && !isPlaceholderMemory(p)) {
            throw new IllegalArgumentException("p is NOT UnicornPointer");
        }
    }

    private boolean isPlaceholderMemory(Pointer p) {
        return "native@0x0".equals(p.toString());
    }

    public void pack() {
        super.write();
    }

    public void unpack() {
        super.read();
    }

}
