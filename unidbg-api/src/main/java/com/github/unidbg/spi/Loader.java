package com.github.unidbg.spi;

import com.github.unidbg.LibraryResolver;
import com.github.unidbg.Module;
import com.github.unidbg.ModuleListener;
import com.github.unidbg.Symbol;
import com.github.unidbg.hook.HookListener;
import com.github.unidbg.pointer.UnidbgPointer;

import java.io.File;
import java.util.Collection;
import java.util.Map;

@SuppressWarnings("unused")
public interface Loader {

    void setLibraryResolver(LibraryResolver libraryResolver);

    void disableCallInitFunction();

    Module load(File elfFile);
    Module load(File elfFile, boolean forceCallInit);

    Module load(LibraryFile libraryFile);
    Module load(LibraryFile libraryFile, boolean forceCallInit);

    Module findModuleByAddress(long address);
    Module findModule(String soName);

    Module dlopen(String filename);
    Module dlopen(String filename, boolean calInit);
    boolean dlclose(long handle);
    Symbol dlsym(long handle, String symbol);

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
    Module loadVirtualModule(String name, final Map<String, UnidbgPointer> symbols);

}
