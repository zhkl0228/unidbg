package cn.banny.unidbg.linux.android.dvm.array;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.linux.android.dvm.Array;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;

public interface PrimitiveArray<T> extends Array<T> {

    UnicornPointer _GetArrayCritical(Emulator emulator, Pointer isCopy);

    void _ReleaseArrayCritical(Pointer elems, int mode);

}
