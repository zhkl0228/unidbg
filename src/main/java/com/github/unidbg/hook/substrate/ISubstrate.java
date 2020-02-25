package com.github.unidbg.hook.substrate;

import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.hook.IHook;
import com.github.unidbg.hook.ReplaceCallback;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.sun.jna.Pointer;

public interface ISubstrate extends IHook {

    /**
     * MSImageRef MSGetImageByName(const char *file);
     * @param file Absolute canonical path of a shared object or dynamic library to query from loaded images.
     * @return Reference to image that can be used with other APIs or NULL if the image is not currently loaded.
     */
    Module getImageByName(String file);

    /**
     * void *MSFindSymbol(MSImageRef image, const char *name);
     * @param image Either a valid image reference (as returned by a previous call of MSGetImageByName) or NULL, to indicate "any image".
     * @param name Name of a raw image symbol to search for. This is not a high-level symbol as used by dlopen: it might require prefixed underscores or other platform-specific mangling.
     * @return Address of symbol (adjusting as typical for ARM/Thumb) or NULL if the symbol could not be located.
     */
    Symbol findSymbol(Module image, String name);

    /**
     * void MSHookFunction(void *symbol, void *hook, void **old);
     * @param symbol The address of code to instrument with replacement code. This is normally, but need not be, a function.
     */
    void hookFunction(Symbol symbol, ReplaceCallback callback);
    @SuppressWarnings("unused")
    void hookFunction(long address, ReplaceCallback callback);
    void hookFunction(Symbol symbol, ReplaceCallback callback, boolean enablePostCall);
    void hookFunction(long address, ReplaceCallback callback, boolean enablePostCall);

    /**
     * void MSHookMessageEx(Class _class, SEL message, IMP hook, IMP *old);
     * @param _class Objective-C class on which a message will be instrumented. This class can be a meta-class (obtained directly using objc_getMetaClass or by calling object_getClass on a class), so as to allow hooking non-instance or "class" messages.
     * @param message Objective-C selector of message that will be instrumented. This might be a literal using @selector or generated at runtime with sel_registerName.
     */
    void hookMessageEx(Pointer _class, Pointer message, ReplaceCallback callback);
    void hookMessageEx(ObjcClass _class, Pointer message, ReplaceCallback callback);
    void hookMessageEx(Pointer _class, Pointer message, ReplaceCallback callback, boolean enablePostCall);
    void hookMessageEx(ObjcClass _class, Pointer message, ReplaceCallback callback, boolean enablePostCall);

}
