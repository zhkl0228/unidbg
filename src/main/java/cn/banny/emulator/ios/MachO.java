package cn.banny.emulator.ios;

interface MachO {

    long CPU_SUBTYPE_ARM_V7 = 9;

    int SECTION_TYPE = 0x000000ff;
    int S_NON_LAZY_SYMBOL_POINTERS = 0x6;
    int S_LAZY_SYMBOL_POINTERS = 0x7;

    long INDIRECT_SYMBOL_ABS = 0x40000000L;
    long INDIRECT_SYMBOL_LOCAL = 0x80000000L;

}
