package com.github.unidbg.ios.gpb;

enum GPBFieldType {

    /** Optional/required field. Only valid for proto2 fields. */
    GPBFieldTypeSingle,
    /** Repeated field. */
    GPBFieldTypeRepeated,
    /** Map field. */
    GPBFieldTypeMap;

    static GPBFieldType of(int fieldType) {
        for (GPBFieldType type : GPBFieldType.values()) {
            if (fieldType == type.ordinal()) {
                return type;
            }
        }
        throw new UnsupportedOperationException("fieldType=" + fieldType);
    }

}
