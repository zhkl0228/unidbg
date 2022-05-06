package com.github.unidbg.ios.gpb;

import com.github.unidbg.Emulator;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import com.github.unidbg.memory.MemoryBlock;
import com.sun.jna.Pointer;

class GPBEnumDescriptor {

    private final ObjcObject descriptor;
    private final String name;

    public GPBEnumDescriptor(ObjcObject descriptor) {
        this.descriptor = descriptor;

        name = descriptor.callObjc("name").toNSString().getString();
    }

    String getName() {
        return name;
    }

    final String buildMsgDef(Emulator<?> emulator, String msgName) {
        StringBuilder builder = new StringBuilder();
        String prefix = msgName + "_";
        String name = this.name;
        if (name.startsWith(prefix)) {
            name = name.substring(prefix.length());
        }
        builder.append("enum ").append(name).append(" {\n");

        MemoryBlock block = emulator.getMemory().malloc(4, false);
        Pointer ptr = block.getPointer();
        ptr.setInt(0, 0);
        int enumNameCount = descriptor.callObjcInt("enumNameCount");
        for (int i = 0; i < enumNameCount; i++) {
            ObjcObject enumNameObject = descriptor.callObjc("getEnumNameForIndex:", i);
            String enumName = enumNameObject.toNSString().getString();
            prefix = this.name + "_";
            if (enumName.startsWith(prefix)) {
                enumName = enumName.substring(prefix.length());
            }
            if (descriptor.callObjcInt("getValue:forEnumName:", ptr, enumNameObject) != 1) {
                throw new IllegalStateException();
            }
            builder.append("  ").append(enumName).append(" = ").append(ptr.getInt(0)).append(";\n");
        }
        block.free();

        builder.append("}");
        return builder.toString();
    }

}
