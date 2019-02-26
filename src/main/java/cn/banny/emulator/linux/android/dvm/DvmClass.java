package cn.banny.emulator.linux.android.dvm;

import cn.banny.emulator.Emulator;
import cn.banny.emulator.linux.Module;
import cn.banny.emulator.pointer.UnicornPointer;
import net.fornwall.jelf.ElfSymbol;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.util.*;

public class DvmClass extends DvmObject<String> implements Hashable {

    private static final Log log = LogFactory.getLog(DvmClass.class);

    public final BaseVM vm;

    DvmClass(BaseVM vm, String className) {
        super("java/lang/Class".equals(className) ? null : vm.resolveClass("java/lang/Class"), className);
        this.vm = vm;
    }

    public String getClassName() {
        return value;
    }

    public DvmObject newObject(Object value) {
        DvmObject obj = new DvmObject<>(this, value);
        vm.addObject(obj, false);
        return obj;
    }

    final Map<Long, DvmMethod> staticMethodMap = new HashMap<>();

    int getStaticMethodID(String methodName, String args) {
        String name = getClassName() + "->" + methodName + args;
        long hash = name.hashCode() & 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("getStaticMethodID name=" + name + ", hash=0x" + Long.toHexString(hash));
        }
        staticMethodMap.put(hash, new DvmMethod(this, methodName, args));
        return (int) hash;
    }

    final Map<Long, DvmMethod> methodMap = new HashMap<>();

    int getMethodID(String methodName, String args) {
        String name = getClassName() + "->" + methodName + args;
        long hash = name.hashCode() & 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("getMethodID name=" + name + ", hash=0x" + Long.toHexString(hash));
        }
        methodMap.put(hash, new DvmMethod(this, methodName, args));
        return (int) hash;
    }

    final Map<Long, DvmField> fieldMap = new HashMap<>();

    int getFieldID(String fieldName, String fieldType) {
        String name = getClassName() + "->" + fieldName + ":" + fieldType;
        long hash = name.hashCode() & 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("getFieldID name=" + name + ", hash=0x" + Long.toHexString(hash));
        }
        fieldMap.put(hash, new DvmField(this, fieldName, fieldType));
        return (int) hash;
    }

    final Map<Long, DvmField> staticFieldMap = new HashMap<>();

    int getStaticFieldID(String fieldName, String fieldType) {
        String name = getClassName() + "->" + fieldName + ":" + fieldType;
        long hash = name.hashCode() & 0xffffffffL;
        if (log.isDebugEnabled()) {
            log.debug("getStaticFieldID name=" + name + ", hash=0x" + Long.toHexString(hash));
        }
        staticFieldMap.put(hash, new DvmField(this, fieldName, fieldType));
        return (int) hash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DvmClass dvmClass = (DvmClass) o;
        return Objects.equals(getClassName(), dvmClass.getClassName());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getClassName());
    }

    @Override
    public String toString() {
        return getClassName();
    }

    final Map<String, UnicornPointer> nativesMap = new HashMap<>();

    UnicornPointer findNativeFunction(Emulator emulator, String method) {
        UnicornPointer fnPtr = nativesMap.get(method);
        int index = method.indexOf('(');
        if (fnPtr == null && index != -1) {
            try {
                String symbolName = "Java_" + getClassName().replace('/', '_') + "_" + method.substring(0, index);
                for (Module module : emulator.getMemory().getLoadedModules()) {
                    ElfSymbol symbol = module.getELFSymbolByName(symbolName);
                    if (symbol != null) {
                        fnPtr = UnicornPointer.pointer(emulator, module.base + symbol.value);
                        break;
                    }
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        if (fnPtr == null) {
            throw new IllegalArgumentException("find method failed: " + method);
        }
        return fnPtr;
    }

    public Number callStaticJniMethod(Emulator emulator, String method, Object...args) {
        UnicornPointer fnPtr = findNativeFunction(emulator, method);
        List<Object> list = new ArrayList<>(10);
        list.add(vm.getJNIEnv());
        list.add(this.hashCode());
        if (args != null) {
            Collections.addAll(list, args);
        }
        return Module.emulateFunction(emulator, fnPtr.peer, list.toArray())[0];
    }

}
