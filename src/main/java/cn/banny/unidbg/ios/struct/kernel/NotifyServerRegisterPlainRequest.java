package cn.banny.unidbg.ios.struct.kernel;

import cn.banny.unidbg.pointer.UnicornStructure;
import com.sun.jna.Pointer;

import java.util.Arrays;
import java.util.List;

public class NotifyServerRegisterPlainRequest extends UnicornStructure {

    public NotifyServerRegisterPlainRequest(Pointer p) {
        super(p);
    }

    public int pad;
    public int name;
    public int nameCnt;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("pad", "name", "nameCnt");
    }

}
