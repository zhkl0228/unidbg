package cn.banny.unidbg.ios.struct;

import cn.banny.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class DyldImageInfo extends UnicornStructure {

    public DyldImageInfo(Pointer p) {
        super(p);
    }

    public Pointer imageLoadAddress;
    public Pointer imageFilePath;
    public int imageFileModDate;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("imageLoadAddress", "imageFilePath", "imageFileModDate");
    }

}
