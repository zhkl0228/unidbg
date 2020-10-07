package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class NDR_record extends UnidbgStructure {

    public NDR_record(Pointer p) {
        super(p);
    }

    public byte mig_vers;
    public byte if_vers;
    public byte reserved1;
    public byte mig_encoding;
    public byte int_rep;
    public byte char_rep;
    public byte float_rep;
    public byte reserved2;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("mig_vers", "if_vers", "reserved1", "mig_encoding", "int_rep", "char_rep", "float_rep", "reserved2");
    }

}
