package cn.banny.unidbg.ios.struct.kernel;

import cn.banny.unidbg.file.StatStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class Stat extends StatStructure {

    public Stat(Pointer p) {
        super(p);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("st_dev", "st_mode", "st_nlink", "st_ino", "st_uid", "st_gid", "st_rdev",
                "st_atimespec", "st_mtimespec", "st_ctimespec", "st_birthtimespec",
                "st_size", "st_blocks", "st_blksize", "st_flags", "st_gen");
    }

}
