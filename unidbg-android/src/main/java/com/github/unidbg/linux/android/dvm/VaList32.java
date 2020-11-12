package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Arrays;

class VaList32 extends VaList {

    private static final Log log = LogFactory.getLog(VaList32.class);

    VaList32(Emulator<?> emulator, BaseVM vm, UnidbgPointer va_list, DvmMethod method) {
        super(vm, method, method.decodeArgsShorty());

        Shorty[] shorties = method.decodeArgsShorty();

        if (shorties.length > 0) {
            UnidbgPointer pointer = va_list;
            for (Shorty shorty : shorties) {
                switch (shorty.getType()) {
                    case 'L':
                    case 'B':
                    case 'C':
                    case 'I':
                    case 'S':
                    case 'Z': {
                        buffer.putInt(pointer.getInt(0));
                        pointer = (UnidbgPointer) pointer.share(4);
                        break;
                    }
                    case 'D': {
                        Pointer ptr = UnidbgPointer.pointer(emulator, (pointer.toUIntPeer() + 7) & 0xfffffff8L);
                        assert ptr != null;
                        buffer.putDouble(ptr.getDouble(0));
                        pointer = (UnidbgPointer) ptr.share(8);
                        break;
                    }
                    case 'F': {
                        Pointer ptr = UnidbgPointer.pointer(emulator, (pointer.toUIntPeer() + 7) & 0xfffffff8L);
                        assert ptr != null;
                        buffer.putFloat((float) ptr.getDouble(0));
                        pointer = (UnidbgPointer) ptr.share(8);
                        break;
                    }
                    case 'J': {
                        Pointer ptr = UnidbgPointer.pointer(emulator, (pointer.toUIntPeer() + 7) & 0xfffffff8L);
                        assert ptr != null;
                        buffer.putLong(ptr.getLong(0));
                        pointer = (UnidbgPointer) ptr.share(8);
                        break;
                    }
                    default:
                        throw new IllegalStateException("c=" + shorty.getType());
                }
            }
        }

        buffer.flip();
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(buffer.array(), "VaList64 args=" + method.args + ", shorty=" + Arrays.toString(shorties)));
        }
    }
}
