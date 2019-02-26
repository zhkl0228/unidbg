package cn.banny.emulator.hook;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.LibraryFile;
import cn.banny.emulator.linux.android.URLibraryFile;

import java.net.URL;

public abstract class BaseHook {

    protected static LibraryFile resolveLibrary(Emulator emulator, String soName) {
        final String abi = emulator.getPointerSize() == 4 ? "armeabi-v7a" : "arm64-v8a";
        URL url = BaseHook.class.getResource("/android/lib/" + abi + "/" + soName);
        if (url == null) {
            throw new IllegalStateException("resolve library failed: " + soName);
        }
        return new URLibraryFile(url, soName, -1);
    }

}
