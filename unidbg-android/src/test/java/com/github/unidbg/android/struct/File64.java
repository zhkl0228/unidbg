package com.github.unidbg.android.struct;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class File64 extends UnidbgStructure {

    public static class __sbuf extends UnidbgStructure {
        public __sbuf(Pointer p) {
            super(p);
        }
        public long _base; // ptr
        public long _size;
        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("_base", "_size");
        }
    }

    public File64(Pointer p) {
        super(p);
        unpack();
    }

    public long _p; // ptr
    public int _r;
    public int _w;
    public int _flags;
    public int _file;
    public __sbuf _bf;
    public int _lbfsize;
    public long _cookie; // ptr
    public long _close; // ptr
    public long _read; // ptr
    public long _seek; // ptr
    public long _write; // ptr
    public __sbuf _ext;
    public long _up; // ptr
    public int _ur;
    public byte[] _ubuf = new byte[3];
    public byte[] _nbuf = new byte[1];
    public __sbuf _lb;
    public int _blksize;
    public long _offset;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("_p", "_r", "_w", "_flags", "_file", "_bf", "_lbfsize", "_cookie", "_close", "_read", "_seek", "_write",
                "_ext", "_up", "_ur", "_ubuf", "_nbuf", "_lb", "_blksize", "_offset");
    }
}
