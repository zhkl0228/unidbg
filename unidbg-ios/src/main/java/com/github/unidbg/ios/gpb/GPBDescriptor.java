package com.github.unidbg.ios.gpb;

import com.github.unidbg.Emulator;
import com.github.unidbg.ios.objc.NSArray;
import com.github.unidbg.ios.objc.NSString;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * <a href="https://github.com/protocolbuffers/protobuf/blob/main/objectivec/GPBDescriptor.h">protobuf</a>
 */
public class GPBDescriptor {

    private static final Logger log = LoggerFactory.getLogger(GPBDescriptor.class);

    private final Emulator<?> emulator;
    private final ObjcObject descriptor;

    public static String toProtobufDef(Emulator<?> emulator, ObjC objc, String msgClass) {
        ObjcClass objcClass = objc.getClass(msgClass);
        boolean hasDescriptor = objc.respondsToSelector(objcClass, "descriptor");
        if (hasDescriptor) {
            ObjcObject descriptor = objcClass.callObjc("descriptor");
            return new GPBDescriptor(emulator, descriptor).buildMsgDef();
        } else {
            throw new UnsupportedOperationException(objcClass.getName() + " is NOT protobuf class");
        }
    }

    private GPBDescriptor(Emulator<?> emulator, ObjcObject descriptor) {
        this.emulator = emulator;
        this.descriptor = descriptor;
    }

    private String buildMsgDef() {
        StringBuilder builder = new StringBuilder();

        ObjcObject file = descriptor.callObjc("file");
        String _package = file.callObjc("package").toNSString().getString();
        ObjcObject obj = file.callObjc("objcPrefix");
        NSString nsString = obj == null ? null : obj.toNSString();
        String objcPrefix = nsString == null ? null : nsString.getString();
        builder.append("// package=").append(_package).append(", objcPrefix=").append(objcPrefix).append("\n");

        String name = descriptor.callObjc("name").toNSString().getString();
        builder.append("message ").append(name).append(" {\n");

        List<GPBEnumDescriptor> enumDescriptors = new ArrayList<>();
        ObjcObject fieldsObject = descriptor.callObjc("fields");
        if (fieldsObject == null) {
            log.warn("descriptor={}", descriptor.getDescription());
        } else {
            NSArray fields = fieldsObject.toNSArray();
            for (ObjcObject field : fields) {
                String fieldName = field.callObjc("name").toNSString().getString();
                int number = field.callObjcInt("number");
                int dataTypeValue = field.callObjcInt("dataType");
                int required = field.callObjcInt("isRequired");
                int optional = field.callObjcInt("isOptional");
                int fieldTypeValue = field.callObjcInt("fieldType");
                int hasDefaultValue = field.callObjcInt("hasDefaultValue");
                if (hasDefaultValue != 0) {
                    log.warn("hasDefaultValue={}", hasDefaultValue);
                }

                builder.append("  ");
                GPBFieldType fieldType = GPBFieldType.of(fieldTypeValue);
                switch (fieldType) {
                    case GPBFieldTypeSingle: {
                        if (required == optional) {
                            throw new IllegalStateException("fieldName=" + fieldName + ", fieldType=" + fieldTypeValue + ", required=" + required);
                        }
                        if (optional != 0) {
                            builder.append("optional ");
                        }
                        break;
                    }
                    case GPBFieldTypeRepeated:
                        builder.append("repeated ");
                        break;
                    case GPBFieldTypeMap: {
                        int mapKeyDataType = field.callObjcInt("mapKeyDataType");
                        GPBDataType dataType = GPBDataType.of(mapKeyDataType);
                        builder.append("map<").append(dataType.buildMsgDef(field, name, GPBFieldType.GPBFieldTypeSingle, enumDescriptors)).append(", ");
                        break;
                    }
                    default:
                        throw new UnsupportedOperationException("fieldType=" + fieldType);
                }
                GPBDataType dataType = GPBDataType.of(dataTypeValue);
                builder.append(dataType.buildMsgDef(field, name, fieldType, enumDescriptors));
                builder.append(" ");
                builder.append(fieldName);
                builder.append(" = ").append(number).append(";");
                builder.append("\n");
            }
        }

        builder.append("}");

        for (GPBEnumDescriptor descriptor : enumDescriptors) {
            builder.append("\n").append(descriptor.buildMsgDef(emulator, name));
        }

        return builder.toString();
    }
}
