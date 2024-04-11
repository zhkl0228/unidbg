const buildDataTypeMsgDef = function (field, name, isFieldTypeMap, enumDescriptors, dataType) {
    let buffer = "";
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
            const msgClass = field.msgClass();
            buffer += msgClass;
            if(isFieldTypeMap) {
                buffer += "> ";
            }
            break;
        case 16: // GPBDataTypeGroup
            break;
        case 17: // GPBDataTypeEnum
            const enumDescriptor = field.enumDescriptor();
            let enumName = enumDescriptor.name().toString();
            const prefix = name.toString() + "_";
            if (enumName.startsWith(prefix)) {
                const length = prefix.length;
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

const buildEnumMsgDef = function (msgName, descriptor) {
    let buffer = "";
    let prefix = msgName + "_";
    let name = descriptor.name().toString();
    if (name.startsWith(prefix)) {
        name = name.substring(prefix.length);
    }
    buffer += ("enum " + name + " {\n");
    const enumNameCount = descriptor.enumNameCount();
    const ptr = Memory.alloc(4);
    for (let i = 0; i < enumNameCount; i++) {
        const enumNameObject = descriptor.getEnumNameForIndex_(i);
        let enumName = enumNameObject.toString();
        prefix = descriptor.name() + "_";
        if (enumName.startsWith(prefix)) {
            enumName = enumName.substring(prefix.length);
        }
        const status = descriptor.getValue_forEnumName_(ptr, enumNameObject);
        if (!status) {
            console.warn("Read " + enumName + " value failed.")
        }
        buffer += ("  " + enumName + " = " + ptr.readU32() + ";\n");
    }
    buffer += "}";
    return buffer;
}

const buildMsgDef = function (descriptor) {
    const file = descriptor.file();
    const _package = file.package();
    const objcPrefix = file.objcPrefix();
    let buffer = "// package=" + _package + ", objcPrefix=" + objcPrefix + "\n";

    const name = descriptor.name();
    buffer += ("message " + name + " {\n")

    const GPBFieldTypeMap = 2;
    const enumDescriptors = [];
    const fields = descriptor.fields();
    for (let i = 0; i < fields.count(); i++) {
        const field = fields.objectAtIndex_(i);
        const fieldName = field.name();
        const number = field.number();
        const dataType = field.dataType();
        const required = field.isRequired();
        const optional = field.isOptional();
        const fieldType = field.fieldType();
        if (field.hasDefaultValue()) {
            console.log(name + "." + fieldName + " has default value.")
        }
        buffer += "  ";

        switch (fieldType) {
            case 0: { // GPBFieldTypeSingle
                if (required === optional) {
                    console.log("fieldName=" + fieldName + ", required=" + required);
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
                const mapKeyDataType = field.mapKeyDataType();
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

    for (let m = 0; m < enumDescriptors.length; m++) {
        console.log(buildEnumMsgDef(name, enumDescriptors[m]));
    }

    return buffer;
}

const list_gpbs = function (filter) {
    console.log("Try list gpbs: " + filter)
    for (const className in ObjC.classes) {
        if (filter) {
            if (className.toLowerCase().indexOf(filter.toLowerCase()) === -1) {
                continue;
            }
        }
        const cGPBMessage = ObjC.classes[className];
        const descriptorMethod = cGPBMessage["- descriptor"];
        if (typeof descriptorMethod === "function") {
            try {
                const descriptor = cGPBMessage.descriptor();
                if (descriptor.className().toString() === "GPBDescriptor") {
                    console.log(cGPBMessage)
                }
            } catch(error) {
            }
        }
    }
};

function gpb(className) {
    if (ObjC.available) {
        const cGPBMessage = ObjC.classes[className];
        if (cGPBMessage) {
            const descriptorMethod = cGPBMessage["- descriptor"];
            if (descriptorMethod) {
                const descriptor = cGPBMessage.descriptor();
                if (descriptor.className().toString() === "GPBDescriptor") {
                    console.log(buildMsgDef(descriptor));
                } else {
                    console.log(cGPBMessage + " is not GPBDescriptor");
                    list_gpbs(className);
                }
            } else {
                console.log(cGPBMessage + " no descriptor method.");
                list_gpbs(className);
            }
        } else {
            list_gpbs(className);
        }
    } else {
        console.log("Objc unavailable")
    }
}
