package cn.banny.unidbg.linux.android.dvm;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class VaList64 extends VaList {

    private static final Log log = LogFactory.getLog(VaList64.class);

    private final BaseVM vm;
    private final ByteBuffer buffer;

    VaList64(Emulator emulator, BaseVM vm, UnicornPointer va_list, DvmMethod method) {
        super(method);
        this.vm = vm;

        long base_p = va_list.getLong(0);
        long base_integer = va_list.getLong(8);
        long base_float = va_list.getLong(16);
        int mask_integer = va_list.getInt(24);
        int mask_float = va_list.getInt(28);

        String shorty = method.decodeArgsShorty();

        char[] chars = shorty.toCharArray();
        if (chars.length == 0) {
            buffer = ByteBuffer.allocate(0);
        } else {
            int total = 0;
            for (char c : chars) {
                switch (c) {
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
                        throw new IllegalStateException("c=" + c);
                }
            }

            buffer = ByteBuffer.allocate(total);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            for (char c : chars) {
                switch (c) {
                    case 'B':
                    case 'C':
                    case 'I':
                    case 'S':
                    case 'Z': {
                        Pointer pointer;
                        if ((mask_integer & 0x80000000) != 0) {
                            if (mask_integer + 8 <= 0) {
                                pointer = UnicornPointer.pointer(emulator, base_integer + mask_integer);
                                mask_integer += 8;
                            } else {
                                pointer = UnicornPointer.pointer(emulator, base_p);
                                mask_integer += 8;
                                base_p = (base_p + 11) & 0xfffffffffffffff8L;
                            }
                        } else {
                            pointer = UnicornPointer.pointer(emulator, base_p);
                            base_p = (base_p + 11) & 0xfffffffffffffff8L;
                        }
                        assert pointer != null;
                        buffer.putInt(pointer.getInt(0));
                        break;
                    }
                    case 'D': {
                        Pointer pointer;
                        if ((mask_float & 0x80000000) != 0) {
                            if (mask_float + 16 <= 0) {
                                pointer = UnicornPointer.pointer(emulator, base_float + mask_float);
                                mask_float += 16;
                            } else {
                                pointer = UnicornPointer.pointer(emulator, base_p);
                                mask_float += 16;
                                base_p = (base_p + 15) & 0xfffffffffffffff8L;
                            }
                        } else {
                            pointer = UnicornPointer.pointer(emulator, base_p);
                            base_p = (base_p + 15) & 0xfffffffffffffff8L;
                        }
                        assert pointer != null;
                        buffer.putDouble(pointer.getDouble(0));
                        break;
                    }
                    case 'F': {
                        Pointer pointer;
                        if ((mask_float & 0x80000000) != 0) {
                            if (mask_float + 16 <= 0) {
                                pointer = UnicornPointer.pointer(emulator, base_float + mask_float);
                                mask_float += 16;
                            } else {
                                pointer = UnicornPointer.pointer(emulator, base_p);
                                mask_float += 16;
                                base_p = (base_p + 15) & 0xfffffffffffffff8L;
                            }
                        } else {
                            pointer = UnicornPointer.pointer(emulator, base_p);
                            base_p = (base_p + 15) & 0xfffffffffffffff8L;
                        }
                        assert pointer != null;
                        buffer.putFloat((float) pointer.getDouble(0));
                        break;
                    }
                    case 'J': {
                        Pointer pointer;
                        if ((mask_integer & 0x80000000) != 0) {
                            if (mask_integer + 8 <= 0) {
                                pointer = UnicornPointer.pointer(emulator, base_integer + mask_integer);
                                mask_integer += 8;
                            } else {
                                pointer = UnicornPointer.pointer(emulator, base_p);
                                mask_integer += 8;
                                base_p = (base_p + 15) & 0xfffffffffffffff8L;
                            }
                        } else {
                            pointer = UnicornPointer.pointer(emulator, base_p);
                            base_p = (base_p + 15) & 0xfffffffffffffff8L;
                        }
                        assert pointer != null;
                        buffer.putLong(pointer.getLong(0));
                        break;
                    }
                    case 'L': {
                        Pointer pointer;
                        if ((mask_integer & 0x80000000) != 0) {
                            if (mask_integer + 8 <= 0) {
                                pointer = UnicornPointer.pointer(emulator, base_integer + mask_integer);
                                mask_integer += 8;
                            } else {
                                pointer = UnicornPointer.pointer(emulator, base_p);
                                mask_integer += 8;
                                base_p = (base_p + 15) & 0xfffffffffffffff8L;
                            }
                        } else {
                            pointer = UnicornPointer.pointer(emulator, base_p);
                            base_p = (base_p + 15) & 0xfffffffffffffff8L;
                        }
                        assert pointer != null;
                        buffer.putInt(pointer.getInt(0));
                        break;
                    }
                    default:
                        throw new IllegalStateException("c=" + c);
                }
            }
        }

        buffer.flip();
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(buffer.array(), "VaList64 base_p=0x" + Long.toHexString(base_p) + ", base_integer=0x" + Long.toHexString(base_integer) + ", base_float=0x" + Long.toHexString(base_float) + ", mask_integer=0x" + Long.toHexString(mask_integer & 0xffffffffL) + ", mask_float=0x" + Long.toHexString(mask_float & 0xffffffffL) + ", args=" + method.args + ", shorty=" + shorty));
        }
    }

    @Override
    public <T extends DvmObject<?>> T getObject(int offset) {
        long p = getInt(offset);
        if (p == 0) {
            return null;
        } else {
            return vm.getObject(p & 0xffffffffL);
        }
    }

    @Override
    public int getInt(int offset) {
        buffer.position(offset);
        return buffer.getInt();
    }

    @Override
    public long getLong(int offset) {
        buffer.position(offset);
        return buffer.getLong();
    }

    @Override
    public float getFloat(int offset) {
        buffer.position(offset);
        return buffer.getFloat();
    }

    @Override
    public double getDouble(int offset) {
        buffer.position(offset);
        return buffer.getDouble();
    }
}
