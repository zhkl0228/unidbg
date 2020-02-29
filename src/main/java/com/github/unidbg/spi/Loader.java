package com.github.unidbg.spi;

import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.ModuleListener;
import com.github.unidbg.Symbol;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.pointer.UnicornPointer;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.Map;

@SuppressWarnings("unused")
public interface Loader {

    void setLibraryResolver(LibraryResolver libraryResolver);

    Module load(File elfFile) throws IOException;
    Module load(File elfFile, boolean forceCallInit) throws IOException;

    Module load(LibraryFile libraryFile) throws IOException;
    Module load(LibraryFile libraryFile, boolean forceCallInit) throws IOException;

    Module findModuleByAddress(long address);
    Module findModule(String soName);

    Module dlopen(String filename) throws IOException;
    Module dlopen(String filename, boolean calInit) throws IOException;
    boolean dlclose(long handle);
    Symbol dlsym(long handle, String symbol) throws IOException;

    void addModuleListener(ModuleListener listener);

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

    /**
     * 加载虚拟模块
     */
    Module loadVirtualModule(String name, final Map<String, UnicornPointer> symbols);

}
