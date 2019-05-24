package cn.banny.unidbg.hook.substrate;

import cn.banny.unidbg.Module;
import cn.banny.unidbg.Symbol;

public interface ISubstrate {

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

}
