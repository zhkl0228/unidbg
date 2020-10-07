package com.github.unidbg.pointer;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

public abstract class UnidbgStructure extends Structure {

    private static final Log log = LogFactory.getLog(UnidbgStructure.class);

    /** Placeholder pointer to help avoid auto-allocation of memory where a
     * Structure needs a valid pointer but want to avoid actually reading from it.
     */
    private static final Pointer PLACEHOLDER_MEMORY = new Pointer(0) {
        @Override
        public Pointer share(long offset, long sz) { return this; }
    };

    public static int calculateSize(Class<? extends UnidbgStructure> type) {
        try {
            Constructor<? extends UnidbgStructure> constructor = type.getConstructor(Pointer.class);
            return constructor.newInstance(PLACEHOLDER_MEMORY).calculateSize(false);
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw new IllegalStateException(e);
        }
    }

    protected UnidbgStructure(Pointer p) {
        super(p);

        checkPointer(p);
    }

    private void checkPointer(Pointer p) {
        if (p == null) {
            throw new NullPointerException("p is null");
        }
        if (!(p instanceof UnidbgPointer) && !isPlaceholderMemory(p)) {
            throw new IllegalArgumentException("p is NOT UnicornPointer");
        }
    }

    @Override
    protected int getNativeSize(Class<?> nativeType, Object value) {
        if (Pointer.class.isAssignableFrom(nativeType)) {
            Emulator<?> emulator = AbstractEmulator.getContextEmulator();
            if (emulator == null) {
                log.warn("getNativeSize context emulator is null");
            }
            return emulator == null ? Native.POINTER_SIZE : emulator.getPointerSize();
        }

        return super.getNativeSize(nativeType, value);
    }

    @Override
    protected int getNativeAlignment(Class<?> type, Object value, boolean isFirstElement) {
        if (Pointer.class.isAssignableFrom(type)) {
            Emulator<?> emulator = AbstractEmulator.getContextEmulator();
            return emulator == null ? Native.POINTER_SIZE : emulator.getPointerSize();
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
