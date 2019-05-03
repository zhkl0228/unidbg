package cn.banny.emulator.pointer;

import cn.banny.emulator.AbstractEmulator;
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

    @Override
    protected int getNativeSize(Class<?> nativeType, Object value) {
        if (Pointer.class.isAssignableFrom(nativeType)) {
            return AbstractEmulator.POINTER_SIZE;
        }

        return super.getNativeSize(nativeType, value);
    }

    @Override
    protected int getNativeAlignment(Class<?> type, Object value, boolean isFirstElement) {
        if (Pointer.class.isAssignableFrom(type)) {
            return AbstractEmulator.POINTER_SIZE;
        }

        return super.getNativeAlignment(type, value, isFirstElement);
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
