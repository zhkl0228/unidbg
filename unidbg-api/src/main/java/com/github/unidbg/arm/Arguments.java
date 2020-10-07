package com.github.unidbg.arm;

import com.github.unidbg.ByteArrayNumber;
import com.github.unidbg.StringNumber;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.ArrayList;
import java.util.List;

public class Arguments {

    private static final Log log = LogFactory.getLog(Arguments.class);

    public final Number[] args;

    Arguments(Memory memory, Number[] args) {
        int i = 0;
        while (args != null && i < args.length) {
            if (args[i] instanceof StringNumber) {
                StringNumber str = (StringNumber) args[i];
                UnidbgPointer pointer = memory.writeStackString(str.value);
                if (log.isDebugEnabled()) {
                    log.debug("map arg" + (i+1) + ": " + pointer + " -> " + args[i]);
                }
                args[i] = pointer.peer;
                pointers.add(pointer.peer);
            } else if (args[i] instanceof ByteArrayNumber) {
                ByteArrayNumber array = (ByteArrayNumber) args[i];
                UnidbgPointer pointer = memory.writeStackBytes(array.value);
                if (log.isDebugEnabled()) {
                    log.debug("map arg" + (i+1) + ": " + pointer + " -> " + Hex.encodeHexString(array.value));
                }
                args[i] = pointer.peer;
                pointers.add(pointer.peer);
            } else if (args[i] == null) {
                args[i] = 0;
            }
            i++;
        }

        this.args = args;
    }

    public final List<Number> pointers = new ArrayList<>(10);

}
