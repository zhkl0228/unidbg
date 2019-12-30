package cn.banny.unidbg.linux.android.dvm;

import java.util.ArrayList;
import java.util.List;

public abstract class VaList {

    public abstract <T extends DvmObject<?>> T getObject(int offset);

    public abstract int getInt(int offset);

    public abstract long getLong(int offset);

    public abstract float getFloat(int offset);

    public abstract double getDouble(int offset);

    private final DvmMethod method;

    protected VaList(DvmMethod method) {
        this.method = method;
    }

    final String formatArgs() {
        String shorty = method.decodeArgsShorty();
        char[] chars = shorty.toCharArray();
        List<String> format = new ArrayList<>(chars.length);
        List<Object> args = new ArrayList<>(chars.length);
        int offset = 0;
        for (char c : chars) {
            switch (c) {
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
                    throw new IllegalStateException("c=" + c);
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

}
