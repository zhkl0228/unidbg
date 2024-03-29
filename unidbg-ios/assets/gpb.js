var buildDataTypeMsgDef = function (field, name, isFieldTypeMap, enumDescriptors, dataType) {
    var buffer = "";
    switch (dataType) {
        case 0: // GPBDataTypeBool
            buffer += "bool";
            break;
        case 1: // GPBDataTypeFixed32
            buffer += "fixed32";
            break;
        case 2: // GPBDataTypeSFixed32
            buffer += "sfixed32";
            break;
        case 3: // GPBDataTypeFloat
            buffer += "float";
            break;
        case 4: // GPBDataTypeFixed64
            buffer += "fixed64";
            break;
        case 5: // GPBDataTypeSFixed64
            buffer += "sfixed64";
            break;
        case 6: // GPBDataTypeDouble
            buffer += "double";
            break;
        case 7: // GPBDataTypeInt32
            buffer += "int32";
            break;
        case 8: // GPBDataTypeInt64
            buffer += "int64";
            break;
        case 9: // GPBDataTypeSInt32
            buffer += "sint32";
            break;
        case 10: // GPBDataTypeSInt64
            buffer += "sint64";
            break;
        case 11: // GPBDataTypeUInt32
            buffer += "uint32";
            break;
        case 12: // GPBDataTypeUInt64
            buffer += "uint64";
            break;
        case 13: // GPBDataTypeBytes
            buffer += "bytes";
            break;
        case 14: // GPBDataTypeString
            buffer += "string";
            break;
        case 15: // GPBDataTypeMessage
            var msgClass = field.msgClass();
            buffer += msgClass;
            if(isFieldTypeMap) {
                buffer += "> ";
            }
            break;
        case 16: // GPBDataTypeGroup
            break;
        case 17: // GPBDataTypeEnum
            var enumDescriptor = field.enumDescriptor();
            var enumName = enumDescriptor.name().toString();
            var prefix = name.toString() + "_";
            if (enumName.startsWith(prefix)) {
                var length = prefix.length;
                enumName = enumName.substring(length);
            }
            buffer += enumName;
            enumDescriptors.push(enumDescriptor);
            break;
        default:
            console.warn("dataType=" + dataType)
            break;
    }
    return buffer;
}

var buildEnumMsgDef = function (msgName, descriptor) {
    var buffer = "";
    var prefix = msgName + "_";
    var name = descriptor.name().toString();
    if (name.startsWith(prefix)) {
        name = name.substring(prefix.length);
    }
    buffer += ("enum " + name + " {\n");
    var enumNameCount = descriptor.enumNameCount();
    var ptr = Memory.alloc(4);
    for (var i = 0; i < enumNameCount; i++) {
        var enumNameObject = descriptor.getEnumNameForIndex_(i);
        var enumName = enumNameObject.toString();
        prefix = descriptor.name() + "_";
        if (enumName.startsWith(prefix)) {
            enumName = enumName.substring(prefix.length);
        }
        var status = descriptor.getValue_forEnumName_(ptr, enumNameObject);
        if (!status) {
            console.warn("Read " + enumName + " value failed.")
        }
        buffer += ("  " + enumName + " = " + ptr.readU32() + ";\n");
    }
    buffer += "}";
    return buffer;
}

var buildMsgDef = function (descriptor) {
    var file = descriptor.file();
    var _package = file.package();
    var objcPrefix = file.objcPrefix();
    var buffer = "// package=" + _package + ", objcPrefix=" + objcPrefix + "\n";

    var name = descriptor.name();
    buffer += ("message " + name + " {\n")

    const GPBFieldTypeMap = 2;
    var enumDescriptors = [];
    var fields = descriptor.fields();
    for (var i = 0; i < fields.count(); i++) {
        var field = fields.objectAtIndex_(i);
        var fieldName = field.name();
        var number = field.number();
        var dataType = field.dataType();
        var required = field.isRequired();
        var optional = field.isOptional();
        var fieldType = field.fieldType();
        if (field.hasDefaultValue()) {
            console.log(name + "." + fieldName + " has default value.")
        }
        buffer += "  ";

        switch (fieldType) {
            case 0: { // GPBFieldTypeSingle
                if (required === optional) {
                    log.warn("fieldName=" + fieldName + ", required=" + required);
                }
                if (optional) {
                    buffer += "optional ";
                }
                break;
            }
            case 1: { // GPBFieldTypeRepeated
                buffer += "repeated ";
                break;
            }
            case GPBFieldTypeMap: {
                var mapKeyDataType = field.mapKeyDataType();
                buffer += ("map<" + buildDataTypeMsgDef(field, name, true, enumDescriptors, mapKeyDataType) + ", ");
                break;
            }
            default:
                console.warn("fieldType=" + fieldType)
                break;
        }
        buffer += buildDataTypeMsgDef(field, name, fieldType === GPBFieldTypeMap, enumDescriptors, dataType);
        buffer += (" " + fieldName + " = " + number + ";\n");
    }

    buffer += "}";

    for (var m = 0; m < enumDescriptors.length; m++) {
        console.log(buildEnumMsgDef(name, enumDescriptors[m]));
    }

    return buffer;
}

function gpb(className) {
    if (ObjC.available) {
        var cGPBMessage = ObjC.classes[className];
        if (cGPBMessage) {
            var descriptorMethod = cGPBMessage["- descriptor"];
            if (descriptorMethod) {
                var descriptor = cGPBMessage.descriptor();
                if (descriptor.className().toString() === "GPBDescriptor") {
                    console.log(buildMsgDef(descriptor));
                } else {
                    console.log(cGPBMessage + " is not GPBDescriptor");
                }
            } else {
                console.log(cGPBMessage + " no descriptor method.");
            }
        } else {
            console.log("NOT found: " + className);
        }
    } else {
        console.log("Objc unavailable")
    }
}
