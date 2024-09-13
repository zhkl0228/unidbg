package com.github.unidbg.ios;

import com.dd.plist.NSDictionary;
import com.dd.plist.NSString;
import com.github.unidbg.arm.backend.BackendFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public abstract class BaseLoader implements Loader {

    private static final Logger log = LoggerFactory.getLogger(BaseLoader.class);

    protected final List<BackendFactory> backendFactories = new ArrayList<>(5);

    public void addBackendFactory(BackendFactory backendFactory) {
        this.backendFactories.add(backendFactory);
    }

    protected boolean overrideResolver;

    public void useOverrideResolver() {
        this.overrideResolver = true;
    }

    protected DarwinResolver createLibraryResolver() {
        return new DarwinResolver();
    }

    protected static String parseExecutable(NSDictionary info) throws IOException {
        NSString bundleExecutable = (NSString) info.get("CFBundleExecutable");
        return bundleExecutable.getContent();
    }

    protected static String parseVersion(NSDictionary info) throws IOException {
        NSString bundleVersion = (NSString) info.get("CFBundleVersion");
        return bundleVersion.getContent();
    }

    protected static String parseCFBundleIdentifier(NSDictionary info) throws IOException {
        NSString bundleIdentifier = (NSString) info.get("CFBundleIdentifier");
        return bundleIdentifier.getContent();
    }

    public static void addEnv(List<String> list) {
        list.add("OBJC_DISABLE_PREOPTIMIZATION=YES"); // disable preoptimization courtesy of dyld shared cache
        list.add("OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES"); // disable safety checks for +initialize after fork
        list.add("OBJC_DISABLE_TAGGED_POINTERS=YES");
        list.add("OBJC_DISABLE_TAG_OBFUSCATION=YES");
        if (log.isDebugEnabled()) {
            list.add("OBJC_HELP=YES"); // describe available environment variables
            list.add("OBJC_PRINT_OPTIONS=YES"); // list which options are set
            list.add("OBJC_PRINT_CLASS_SETUP=YES"); // log progress of class and category setup
            list.add("OBJC_PRINT_INITIALIZE_METHODS=YES"); // log calls to class +initialize methods
            list.add("OBJC_PRINT_PROTOCOL_SETUP=YES"); // log progress of protocol setup
            list.add("OBJC_PRINT_IVAR_SETUP=YES"); // log processing of non-fragile ivars
            list.add("OBJC_PRINT_VTABLE_SETUP=YES"); // log processing of class vtables

            list.add("OBJC_PRINT_IMAGES=YES"); // log image and library names as they are loaded
            list.add("OBJC_PRINT_IMAGE_TIMES=YES"); // measure duration of image loading steps
            list.add("OBJC_PRINT_LOAD_METHODS=YES"); // log calls to class and category +load methods
            list.add("OBJC_PRINT_RESOLVED_METHODS=YES"); // log methods created by +resolveClassMethod: and +resolveInstanceMethod:
            list.add("OBJC_PRINT_PREOPTIMIZATION=YES"); // log preoptimization courtesy of dyld shared cache
            list.add("OBJC_PRINT_EXCEPTIONS=YES"); // log exception handling
            list.add("OBJC_DEBUG_FRAGILE_SUPERCLASSES=YES"); // warn about subclasses that may have been broken by subsequent changes to superclasses
        }
    }

    protected boolean forceCallInit;

    @SuppressWarnings("unused")
    public void setForceCallInit(boolean forceCallInit) {
        this.forceCallInit = forceCallInit;
    }

    public static final String APP_DIR = "/var/containers/Bundle/Application/";

}
