package com.github.unidbg.ios.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Dirent extends UnidbgStructure {

    public static final byte DT_DIR = 4;
    public static final byte DT_REG = 8;

    public Dirent(Pointer p) {
        super(p);
    }

    public long d_fileno; /* file number of entry */
    public long d_seekoff; /* seek offset (optional, used by servers) */
    public short d_reclen; /* length of this record */
    public short d_namlen; /* length of string in d_name */
    public byte d_type; /* file type, see below */
    public byte[] d_name = new byte[1024]; /* name must be no longer than this */

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("d_fileno", "d_seekoff", "d_reclen", "d_namlen", "d_type", "d_name");
    }

}
