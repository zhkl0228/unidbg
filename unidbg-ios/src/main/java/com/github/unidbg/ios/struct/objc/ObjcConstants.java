package com.github.unidbg.ios.struct.objc;

interface ObjcConstants {

    // Values for class_ro_t->flags
    // These are emitted by the compiler and are part of the ABI.
    // class is a metaclass
    int RO_META = (1);

    // class has started realizing but not yet completed it
    int RW_REALIZING = (1<<19);

    int RO_FUTURE = (1<<30); // // class is unrealized future class - must never be set by compiler
    int RW_REALIZED = (1<<31); // class is realized - must never be set by compiler

    long FAST_DATA_MASK = 0x00007ffffffffff8L;

}
