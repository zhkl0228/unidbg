package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

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
                    ByteBuffer buffer = ByteBuffer.allocate(8);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putInt(getInt(offset++));
                    buffer.putInt(getInt(offset++));
                    buffer.flip();
                    args.add(buffer.getDouble());
                    break;
                }
                case 'F': {
                    if (offset % 2 == 0) {
                        offset++;
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(8);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putInt(getInt(offset++));
                    buffer.putInt(getInt(offset++));
                    buffer.flip();
                    args.add((float) buffer.getDouble());
                    break;
                }
                case 'J': {
                    if (offset % 2 == 0) {
                        offset++;
                    }
                    ByteBuffer buffer = ByteBuffer.allocate(8);
                    buffer.order(ByteOrder.LITTLE_ENDIAN);
                    buffer.putInt(getInt(offset++));
                    buffer.putInt(getInt(offset++));
                    buffer.flip();
                    args.add(buffer.getLong());
                    break;
                }
                default:
                    throw new IllegalStateException("c=" + shorty.getType());
            }
        }
    }

}
