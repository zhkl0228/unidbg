package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.Emulator;
import com.github.unidbg.pointer.UnidbgPointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

class VaList32 extends VaList {

    private static final Logger log = LoggerFactory.getLogger(VaList32.class);

    VaList32(Emulator<?> emulator, BaseVM vm, UnidbgPointer va_list, DvmMethod method) {
        super(vm, method);

        UnidbgPointer pointer = va_list;
        for (Shorty shorty : shorties) {
            switch (shorty.getType()) {
                case 'L':
                case 'B':
                case 'C':
                case 'I':
                case 'S':
                case 'Z': {
                    args.add(pointer.getInt(0));
                    pointer = pointer.share(4, 0);
                    break;
                }
                case 'D': {
                    UnidbgPointer ptr = UnidbgPointer.pointer(emulator, (pointer.toUIntPeer() + 7) & 0xfffffff8L);
                    assert ptr != null;
                    args.add(ptr.getDouble(0));
                    pointer = ptr.share(8, 0);
                    break;
                }
                case 'F': {
                    UnidbgPointer ptr = UnidbgPointer.pointer(emulator, (pointer.toUIntPeer() + 7) & 0xfffffff8L);
                    assert ptr != null;
                    args.add((float) ptr.getDouble(0));
                    pointer = ptr.share(8, 0);
                    break;
                }
                case 'J': {
                    UnidbgPointer ptr = UnidbgPointer.pointer(emulator, (pointer.toUIntPeer() + 7) & 0xfffffff8L);
                    assert ptr != null;
                    args.add(ptr.getLong(0));
                    pointer = ptr.share(8, 0);
                    break;
                }
                default:
                    throw new IllegalStateException("c=" + shorty.getType());
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("VaList64 args={}, shorty={}", method.args, Arrays.toString(shorties));
        }
    }
}
