package com.github.unidbg.pointer;

import com.github.unidbg.Emulator;
import com.github.unidbg.PointerArg;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import org.apache.commons.codec.binary.Hex;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.util.Iterator;
import java.util.Map;

public abstract class UnidbgStructure extends Structure implements PointerArg {

    /** Placeholder pointer to help avoid auto-allocation of memory where a
     * Structure needs a valid pointer but want to avoid actually reading from it.
     */
    private static final Pointer PLACEHOLDER_MEMORY = new UnidbgPointer(null, null) {
        @Override
        public UnidbgPointer share(long offset, long sz) { return this; }
    };

    public static int calculateSize(Class<? extends UnidbgStructure> type) {
        try {
            Constructor<? extends UnidbgStructure> constructor = type.getConstructor(Pointer.class);
            return constructor.newInstance(PLACEHOLDER_MEMORY).calculateSize(false);
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw new IllegalStateException(e);
        }
    }

    private static class ByteArrayPointer extends UnidbgPointer {
        private final Emulator<?> emulator;
        private final byte[] data;
        public ByteArrayPointer(Emulator<?> emulator, byte[] data) {
            super(emulator, data);
            this.emulator = emulator;
            this.data = data;
        }
        @Override
        public UnidbgPointer share(long offset, long sz) {
            if (offset == 0) {
                return this;
            }
            if (offset > 0 && offset + sz < data.length) {
                if (sz == 0) {
                    sz = data.length - offset;
                }
                byte[] tmp = new byte[(int) sz];
                System.arraycopy(data, (int) offset, tmp, 0, (int) sz);
                return new ByteArrayPointer(emulator, tmp);
            }
            throw new UnsupportedOperationException("offset=0x" + Long.toHexString(offset) + ", sz=" + sz);
        }
    }

    protected UnidbgStructure(Emulator<?> emulator, byte[] data) {
        this(new ByteArrayPointer(emulator, data));
    }

    protected UnidbgStructure(byte[] data) {
        this(null, data);
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
            throw new IllegalArgumentException("p is NOT UnidbgPointer");
        }
    }

    @Override
    protected int getNativeSize(Class<?> nativeType, Object value) {
        if (Pointer.class.isAssignableFrom(nativeType)) {
            throw new UnsupportedOperationException();
        }

        return super.getNativeSize(nativeType, value);
    }

    @Override
    protected int getNativeAlignment(Class<?> type, Object value, boolean isFirstElement) {
        if (Pointer.class.isAssignableFrom(type)) {
            throw new UnsupportedOperationException();
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

    /**
     * @param debug If true, will include a native memory dump of the
     * Structure's backing memory.
     * @return String representation of this object.
     */
    public String toString(boolean debug) {
        return toString(0, true, debug);
    }

    private String format(Class<?> type) {
        String s = type.getName();
        int dot = s.lastIndexOf(".");
        return s.substring(dot + 1);
    }

    private String toString(int indent, boolean showContents, boolean dumpMemory) {
        ensureAllocated();
        String LS = System.getProperty("line.separator");
        String name = format(getClass()) + "(" + getPointer() + ")";
        if (!(getPointer() instanceof Memory)) {
            name += " (" + size() + " bytes)";
        }
        StringBuilder prefix = new StringBuilder();
        for (int idx=0;idx < indent;idx++) {
            prefix.append("  ");
        }
        StringBuilder contents = new StringBuilder(LS);
        if (!showContents) {
            contents = new StringBuilder("...}");
        }
        else for (Iterator<StructField> i = fields().values().iterator(); i.hasNext();) {
            StructField sf = i.next();
            Object value = getFieldValue(sf.field);
            String type = format(sf.type);
            String index = "";
            contents.append(prefix);
            if (sf.type.isArray() && value != null) {
                type = format(sf.type.getComponentType());
                index = "[" + Array.getLength(value) + "]";
            }
            contents.append(String.format("  %s %s%s@0x%X", type, sf.name, index, sf.offset));
            if (value instanceof UnidbgStructure) {
                value = ((UnidbgStructure)value).toString(indent + 1, !(value instanceof Structure.ByReference), dumpMemory);
            }
            contents.append("=");
            if (value instanceof Long) {
                contents.append(String.format("0x%08X", value));
            }
            else if (value instanceof Integer) {
                contents.append(String.format("0x%04X", value));
            }
            else if (value instanceof Short) {
                contents.append(String.format("0x%02X", value));
            }
            else if (value instanceof Byte) {
                contents.append(String.format("0x%01X", value));
            }
            else if (value instanceof byte[]) {
                contents.append(Hex.encodeHexString((byte[]) value));
            }
            else {
                contents.append(String.valueOf(value).trim());
            }
            contents.append(LS);
            if (!i.hasNext())
                contents.append(prefix).append("}");
        }
        if (indent == 0 && dumpMemory) {
            final int BYTES_PER_ROW = 4;
            contents.append(LS).append("memory dump").append(LS);
            byte[] buf = getPointer().getByteArray(0, size());
            for (int i=0;i < buf.length;i++) {
                if ((i % BYTES_PER_ROW) == 0) contents.append("[");
                if (buf[i] >=0 && buf[i] < 16)
                    contents.append("0");
                contents.append(Integer.toHexString(buf[i] & 0xff));
                if ((i % BYTES_PER_ROW) == BYTES_PER_ROW-1 && i < buf.length-1)
                    contents.append("]").append(LS);
            }
            contents.append("]");
        }
        return name + " {" + contents;
    }

    /** Obtain the value currently in the Java field.  Does not read from
     * native memory.
     * @param field field to look up
     * @return current field value (Java-side only)
     */
    private Object getFieldValue(Field field) {
        try {
            return field.get(this);
        }
        catch (Exception e) {
            throw new Error("Exception reading field '" + field.getName() + "' in " + getClass(), e);
        }
    }

    private static final Field FIELD_STRUCT_FIELDS;

    static {
        try {
            FIELD_STRUCT_FIELDS = Structure.class.getDeclaredField("structFields");
            FIELD_STRUCT_FIELDS.setAccessible(true);
        } catch (NoSuchFieldException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Return all fields in this structure (ordered).  This represents the
     * layout of the structure, and will be shared among Structures of the
     * same class except when the Structure can have a variable size.
     * NOTE: {@link #ensureAllocated()} <em>must</em> be called prior to
     * calling this method.
     * @return {@link Map} of field names to field representations.
     */
    @SuppressWarnings("unchecked")
    private Map<String, StructField> fields() {
        try {
            return (Map<String, StructField>) FIELD_STRUCT_FIELDS.get(this);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }
}
