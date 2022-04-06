package com.github.unidbg.ios.struct.kernel;

import com.github.unidbg.pointer.UnidbgStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class DyldCacheHeader extends UnidbgStructure {

    public byte[] magic; // e.g. "dyld_v0    i386"
    public int mappingOffset; // file offset to first dyld_cache_mapping_info
    public int mappingCount; // number of dyld_cache_mapping_info entries
    public int imagesOffset; // file offset to first dyld_cache_image_info
    public int imagesCount; // number of dyld_cache_image_info entries
    public long dyldBaseAddress; // base address of dyld when cache was built
    public long codeSignatureOffset; // file offset of code signature blob
    public long codeSignatureSize; // size of code signature blob (zero means to end of file)
    public long slideInfoOffset; // file offset of kernel slid info
    public long slideInfoSize; // size of kernel slid info
    public long localSymbolsOffset; // file offset of where local symbols are stored
    public long localSymbolsSize; // size of local symbols information
    public byte[] uuid = new byte[16]; // unique value for each shared cache file

    public DyldCacheHeader(Pointer p) {
        super(p);

        byte[] magic = "dyld_v1  arm64e".getBytes();
        this.magic = Arrays.copyOf(magic, magic.length + 1);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("magic", "mappingOffset", "mappingCount", "imagesOffset", "imagesCount",
                "dyldBaseAddress", "codeSignatureOffset", "codeSignatureSize", "slideInfoOffset", "slideInfoSize",
                "localSymbolsOffset", "localSymbolsSize", "uuid");
    }
}
