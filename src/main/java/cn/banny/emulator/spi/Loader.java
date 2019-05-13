package cn.banny.emulator.spi;

import cn.banny.emulator.*;
import cn.banny.emulator.hook.HookListener;

import java.io.File;
import java.io.IOException;
import java.util.Collection;

public interface Loader {

    void setLibraryResolver(LibraryResolver libraryResolver);

    Module load(File elfFile) throws IOException;
    Module load(File elfFile, boolean forceCallInit) throws IOException;

    Module load(LibraryFile libraryFile) throws IOException;
    Module load(LibraryFile libraryFile, boolean forceCallInit) throws IOException;

    @Deprecated
    byte[] unpack(File elfFile) throws IOException;

    Module findModuleByAddress(long address);
    Module findModule(String soName);

    Module dlopen(String filename) throws IOException;
    Module dlopen(String filename, boolean calInit) throws IOException;
    boolean dlclose(long handle);
    Symbol dlsym(long handle, String symbol) throws IOException;

    void setModuleListener(ModuleListener listener);

    void addHookListener(HookListener listener);

    Collection<Module> getLoadedModules();

    String getMaxLengthLibraryName();
    long getMaxSizeOfLibrary();

    /**
     * 运行线程
     */
    void runThread(int threadId, long timeout);

    /**
     * 运行最后创建的线程
     */
    void runLastThread(long timeout);

    boolean hasThread(int threadId);

}
