package com.github.unidbg.linux.android.dvm;

import java.util.ArrayList;
import java.util.List;

public abstract class VarArg {

    private final BaseVM vm;
    final List<Object> args;
    protected final DvmMethod method;
    protected Shorty[] shorties;

    protected VarArg(BaseVM vm, DvmMethod method) {
        this.vm = vm;
        this.shorties = method.decodeArgsShorty();

        this.method = method;
        this.args = new ArrayList<>(shorties.length);
    }

    /**
     * @param index 0 based
     */
    public final <T extends DvmObject<?>> T getObjectArg(int index) {
        int hash = getIntArg(index);
        return vm.getObject(hash);
    }

    /**
     * @param index 0 based
     */
    public final int getIntArg(int index) {
        return (Integer) args.get(index);
    }

    /**
     * @param index 0 based
     */
    public final long getLongArg(int index) {
        return (Long) args.get(index);
    }

    /**
     * @param index 0 based
     */
    public final float getFloatArg(int index) {
        return (Float) args.get(index);
    }

    /**
     * @param index 0 based
     */
    public final double getDoubleArg(int index) {
        return (Double) args.get(index);
    }


    final String formatArgs() {
        Shorty[] shorties = method.decodeArgsShorty();
        List<String> format = new ArrayList<>(shorties.length);
        List<Object> args = new ArrayList<>(shorties.length);
        for (int i = 0; i < shorties.length; i++) {
            Shorty shorty = shorties[i];
            switch (shorty.getType()) {
                case 'B':
                    format.add("%s");
                    args.add((byte) getIntArg(i));
                    break;
                case 'C':
                    format.add("%c");
                    args.add((char) getIntArg(i));
                    break;
                case 'I':
                    format.add("0x%x");
                    args.add(getIntArg(i));
                    break;
                case 'S':
                    format.add("%s");
                    args.add((short) getIntArg(i));
                    break;
                case 'Z':
                    format.add("%s");
                    args.add(BaseVM.valueOf(getIntArg(i)));
                    break;
                case 'F':
                    format.add("%fF");
                    args.add(getFloatArg(i));
                    break;
                case 'L':
                    format.add("%s");
                    args.add(getObjectArg(i));
                    break;
                case 'D':
                    format.add("%sD");
                    args.add(getDoubleArg(i));
                    break;
                case 'J':
                    format.add("0x%xL");
                    args.add(getLongArg(i));
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

}
