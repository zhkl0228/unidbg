package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;

class ArmVarArg32 extends ArmVarArg {

    ArmVarArg32(Emulator<?> emulator, BaseVM vm, DvmMethod method) {
        super(emulator, vm, method);

        int offset = 0;
        for (Shorty shorty : shorties) {
            switch (shorty.getType()) {
                case 'L':
                case 'B':
                case 'C':
                case 'I':
                case 'S':
                case 'Z': {
                    args.add(getInt(offset++));
                    break;
                }
                case 'D': {
                    if (offset % 2 == 0) {
                        offset++;
                    }
                    long value = (getInt(offset++) & 0xffffffffL) | ((long) getInt(offset++) << 32);
                    args.add(Double.longBitsToDouble(value));
                    break;
                }
                case 'F': {
                    if (offset % 2 == 0) {
                        offset++;
                    }
                    long value = (getInt(offset++) & 0xffffffffL) | ((long) getInt(offset++) << 32);
                    args.add((float) Double.longBitsToDouble(value));
                    break;
                }
                case 'J': {
                    if (offset % 2 == 0) {
                        offset++;
                    }
                    long value = (getInt(offset++) & 0xffffffffL) | ((long) getInt(offset++) << 32);
                    args.add(value);
                    break;
                }
                default:
                    throw new IllegalStateException("c=" + shorty.getType());
            }
        }
    }

}
