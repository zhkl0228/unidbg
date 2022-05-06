package com.github.unidbg.ios.gpb;

import com.github.unidbg.ios.struct.objc.ObjcObject;

import java.util.List;

enum GPBDataType {

    /** Field contains boolean value(s). */
    GPBDataTypeBool("bool"),
    /** Field contains unsigned 4 byte value(s). */
    GPBDataTypeFixed32("fixed32"),
    /** Field contains signed 4 byte value(s). */
    GPBDataTypeSFixed32("sfixed32"),
    /** Field contains float value(s). */
    GPBDataTypeFloat("float"),
    /** Field contains unsigned 8 byte value(s). */
    GPBDataTypeFixed64("fixed64"),
    /** Field contains signed 8 byte value(s). */
    GPBDataTypeSFixed64("sfixed64"),
    /** Field contains double value(s). */
    GPBDataTypeDouble("double"),
    /**
     * Field contains variable length value(s). Inefficient for encoding negative
     * numbers – if your field is likely to have negative values, use
     * GPBDataTypeSInt32 instead.
     **/
    GPBDataTypeInt32("int32"),
    /**
     * Field contains variable length value(s). Inefficient for encoding negative
     * numbers – if your field is likely to have negative values, use
     * GPBDataTypeSInt64 instead.
     **/
    GPBDataTypeInt64("int64"),
    /** Field contains signed variable length integer value(s). */
    GPBDataTypeSInt32("sint32"),
    /** Field contains signed variable length integer value(s). */
    GPBDataTypeSInt64("sint64"),
    /** Field contains unsigned variable length integer value(s). */
    GPBDataTypeUInt32("uint32"),
    /** Field contains unsigned variable length integer value(s). */
    GPBDataTypeUInt64("uint64"),
    /** Field contains an arbitrary sequence of bytes. */
    GPBDataTypeBytes("bytes"),
    /** Field contains UTF-8 encoded or 7-bit ASCII text. */
    GPBDataTypeString("string"),
    /** Field contains message type(s). */
    GPBDataTypeMessage,
    /** Field contains message type(s). */
    GPBDataTypeGroup,
    /** Field contains enum value(s). */
    GPBDataTypeEnum;

    private final String typeName;

    GPBDataType() {
        this(null);
    }

    GPBDataType(String typeName) {
        this.typeName = typeName;
    }

    String getTypeName() {
        return typeName == null ? name() : typeName;
    }

    static GPBDataType of(int dataType) {
        for (GPBDataType type : GPBDataType.values()) {
            if (dataType == type.ordinal()) {
                return type;
            }
        }
        throw new UnsupportedOperationException("dataType=" + dataType);
    }

    final String buildMsgDef(ObjcObject field, String name, GPBFieldType fieldType, List<GPBEnumDescriptor> enumDescriptors) {
        StringBuilder builder = new StringBuilder();
        switch (this) {
            case GPBDataTypeMessage: {
                ObjcObject msgClass = field.callObjc("msgClass");
                if (fieldType == GPBFieldType.GPBFieldTypeMap) {
                    builder.append(msgClass.getDescription()).append("> ");
                } else {
                    builder.append(msgClass.getDescription());
                }
                break;
            }
            case GPBDataTypeEnum: {
                GPBEnumDescriptor enumDescriptor = new GPBEnumDescriptor(field.callObjc("enumDescriptor"));
                String enumName = enumDescriptor.getName();
                String prefix = name + "_";
                if (enumName.startsWith(prefix)) {
                    enumName = enumName.substring(prefix.length());
                }
                builder.append(enumName);
                enumDescriptors.add(enumDescriptor);
                break;
            }
            default:
                builder.append(this.getTypeName());
                break;
        }
        return builder.toString();
    }

}
