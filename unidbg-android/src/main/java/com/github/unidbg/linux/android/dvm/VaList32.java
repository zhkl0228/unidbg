package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class VaList32 extends VaList {

    private static final Log log = LogFactory.getLog(VaList32.class);

    VaList32(Emulator<?> emulator, BaseVM vm, UnicornPointer va_list, DvmMethod method) {
        super(vm, method, method.decodeArgsShorty());

        String shorty = method.decodeArgsShorty();

        char[] chars = shorty.toCharArray();
        if (chars.length > 0) {
            UnicornPointer pointer = va_list;
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
}
