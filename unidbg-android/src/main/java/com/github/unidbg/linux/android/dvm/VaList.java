package com.github.unidbg.linux.android.dvm;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

public abstract class VaList {

    private final BaseVM vm;
    private final DvmMethod method;
    final ByteBuffer buffer;

    protected VaList(BaseVM vm, DvmMethod method, Shorty[] shorties) {
        this.vm = vm;
        this.method = method;

        if (shorties.length == 0) {
            buffer = ByteBuffer.allocate(0);
        } else {
            int total = 0;
            for (Shorty shorty : shorties) {
                switch (shorty.getType()) {
                    case 'B':
                    case 'C':
                    case 'I':
                    case 'S':
                    case 'Z':
                    case 'F':
                    case 'L':
                        total += 4;
                        break;
                    case 'D':
                    case 'J':
                        total += 8;
                        break;
                    default:
                        throw new IllegalStateException("c=" + shorty.getType());
                }
            }
            buffer = ByteBuffer.allocate(total);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
        }
    }

    final String formatArgs() {
        Shorty[] shorties = method.decodeArgsShorty();
        List<String> format = new ArrayList<>(shorties.length);
        List<Object> args = new ArrayList<>(shorties.length);
        int offset = 0;
        for (Shorty shorty : shorties) {
            switch (shorty.getType()) {
                case 'B':
                    format.add("%s");
                    args.add((byte) getInt(offset));
                    offset += 4;
                    break;
                case 'C':
                    format.add("%c");
                    args.add((char) getInt(offset));
                    offset += 4;
                    break;
                case 'I':
                    format.add("0x%x");
                    args.add(getInt(offset));
                    offset += 4;
                    break;
                case 'S':
                    format.add("%s");
                    args.add((short) getInt(offset));
                    offset += 4;
                    break;
                case 'Z':
                    format.add("%s");
                    args.add(getInt(offset) == VM.JNI_TRUE);
                    offset += 4;
                    break;
                case 'F':
                    format.add("%f");
                    args.add(getFloat(offset));
                    offset += 4;
                    break;
                case 'L':
                    format.add("%s");
                    args.add(this.getObject(offset));
                    offset += 4;
                    break;
                case 'D':
                    format.add("%s");
                    args.add(getDouble(offset));
                    offset += 8;
                    break;
                case 'J':
                    format.add("0x%x");
                    args.add(getLong(offset));
                    offset += 8;
                    break;
                default:
                    throw new IllegalStateException("c=" + shorty.getType());
            }
        }
        StringBuilder sb = new StringBuilder();
        if (!format.isEmpty()) {
            sb.append(format.remove(0));
        }
        for (String str : format) {
            sb.append(", ").append(str);
        }
        return String.format(sb.toString(), args.toArray());
    }

    public final <T extends DvmObject<?>> T getObject(int offset) {
        int p = getInt(offset);
        if (p == 0) {
            return null;
        } else {
            return vm.getObject(p);
        }
    }

    public final int getInt(int offset) {
        buffer.position(offset);
        return buffer.getInt();
    }

    public final long getLong(int offset) {
        buffer.position(offset);
        return buffer.getLong();
    }

    public final float getFloat(int offset) {
        buffer.position(offset);
        return buffer.getFloat();
    }

    public final double getDouble(int offset) {
        buffer.position(offset);
        return buffer.getDouble();
    }

}
