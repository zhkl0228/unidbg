package cn.banny.unidbg.linux.android.dvm;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class VaList32 extends VaList {

    private static final Log log = LogFactory.getLog(VaList32.class);

    private final BaseVM vm;
    private final ByteBuffer buffer;

    VaList32(Emulator emulator, BaseVM vm, UnicornPointer va_list, DvmMethod method) {
        super(method);
        this.vm = vm;

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

            UnicornPointer pointer = va_list;
            buffer = ByteBuffer.allocate(total);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            for (char c : chars) {
                switch (c) {
                    case 'L':
                    case 'B':
                    case 'C':
                    case 'I':
                    case 'S':
                    case 'Z': {
                        buffer.putInt(pointer.getInt(0));
                        pointer = (UnicornPointer) pointer.share(4);
                        break;
                    }
                    case 'D': {
                        Pointer ptr = UnicornPointer.pointer(emulator, (pointer.toUIntPeer() + 7) & 0xfffffff8L);
                        assert ptr != null;
                        buffer.putDouble(ptr.getDouble(0));
                        pointer = (UnicornPointer) ptr.share(8);
                        break;
                    }
                    case 'F': {
                        Pointer ptr = UnicornPointer.pointer(emulator, (pointer.toUIntPeer() + 7) & 0xfffffff8L);
                        assert ptr != null;
                        buffer.putFloat((float) ptr.getDouble(0));
                        pointer = (UnicornPointer) ptr.share(8);
                        break;
                    }
                    case 'J': {
                        Pointer ptr = UnicornPointer.pointer(emulator, (pointer.toUIntPeer() + 7) & 0xfffffff8L);
                        assert ptr != null;
                        buffer.putLong(ptr.getLong(0));
                        pointer = (UnicornPointer) ptr.share(8);
                        break;
                    }
                    default:
                        throw new IllegalStateException("c=" + c);
                }
            }
        }

        buffer.flip();
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(buffer.array(), "VaList64 args=" + method.args + ", shorty=" + shorty));
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
