package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.pointer.UnidbgPointer;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class JValueList extends VaList {

    private static final Logger log = LoggerFactory.getLogger(JValueList.class);

    JValueList(BaseVM vm, UnidbgPointer jvalue, DvmMethod method) {
        super(vm, method);

        Pointer pointer = jvalue;
        for (Shorty shorty : shorties) {
            switch (shorty.getType()) {
                case 'L':
                    UnidbgPointer ptr = (UnidbgPointer) pointer.getPointer(0);
                    args.add(ptr == null ? 0 : (int) ptr.toUIntPeer());
                    break;
                case 'B': {
                    byte val = pointer.getByte(0);
                    args.add(val & 0xff);
                    break;
                }
                case 'Z': {
                    byte val = pointer.getByte(0);
                    args.add(val & 1);
                    break;
                }
                case 'C': {
                    char val = pointer.getChar(0);
                    args.add((int) val);
                    break;
                }
                case 'S': {
                    args.add((int) pointer.getShort(0));
                    break;
                }
                case 'I': {
                    args.add(pointer.getInt(0));
                    break;
                }
                case 'F': {
                    args.add((float) pointer.getDouble(0));
                    break;
                }
                case 'D': {
                    args.add(pointer.getDouble(0));
                    break;
                }
                case 'J': {
                    args.add(pointer.getLong(0));
                    break;
                }
                default:
                    throw new IllegalStateException("c=" + shorty.getType());
            }

            pointer = pointer.share(8);
        }

        if (log.isDebugEnabled()) {
            log.debug("JValueList args={}, shorty={}", method.args, shorties);
        }
    }

}
