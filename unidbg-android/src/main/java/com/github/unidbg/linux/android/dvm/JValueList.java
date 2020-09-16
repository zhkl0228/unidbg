package com.github.unidbg.linux.android.dvm;

import com.github.unidbg.pointer.UnicornPointer;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

class JValueList extends VaList {

    private static final Log log = LogFactory.getLog(JValueList.class);

    JValueList(BaseVM vm, UnicornPointer jvalue, DvmMethod method) {
        super(vm, method, method.decodeArgsShorty());

        String shorty = method.decodeArgsShorty();

        char[] chars = shorty.toCharArray();
        if (chars.length > 0) {
            Pointer pointer = jvalue;
            for (char c : chars) {
                switch (c) {
                    case 'L':
                        UnicornPointer ptr = (UnicornPointer) pointer.getPointer(0);
                        buffer.putInt((int) ptr.toUIntPeer());
                        break;
                    case 'B': {
                        byte val = pointer.getByte(0);
                        buffer.putInt(val & 1);
                        break;
                    }
                    case 'Z': {
                        byte val = pointer.getByte(0);
                        buffer.putInt(val & 0xff);
                        break;
                    }
                    case 'C': {
                        char val = pointer.getChar(0);
                        buffer.putInt(val);
                        break;
                    }
                    case 'S': {
                        buffer.putInt(pointer.getShort(0));
                        break;
                    }
                    case 'I': {
                        buffer.putInt(pointer.getInt(0));
                        break;
                    }
                    case 'F': {
                        buffer.putFloat((float) pointer.getDouble(0));
                        break;
                    }
                    case 'D': {
                        buffer.putDouble(pointer.getDouble(0));
                        break;
                    }
                    case 'J': {
                        buffer.putLong(pointer.getLong(0));
                        break;
                    }
                    default:
                        throw new IllegalStateException("c=" + c);
                }

                pointer = pointer.share(8);
            }
        }

        buffer.flip();
        if (log.isDebugEnabled()) {
            log.debug(Inspector.inspectString(buffer.array(), "JValueList args=" + method.args + ", shorty=" + shorty));
        }
    }

}
