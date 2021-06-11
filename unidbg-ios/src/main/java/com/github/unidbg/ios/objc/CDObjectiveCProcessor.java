package com.github.unidbg.ios.objc;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import com.github.unidbg.ios.ExportSymbol;
import com.github.unidbg.ios.MachOModule;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public abstract class CDObjectiveCProcessor {

    final ByteBuffer buffer;
    final Emulator<?> emulator;
    final List<Objc2Class> classList = new ArrayList<>();
    final List<Objc2Category> categoryList = new ArrayList<>();

    CDObjectiveCProcessor(ByteBuffer buffer, Emulator<?> emulator) {
        super();

        this.buffer = buffer;
        this.emulator = emulator;
    }

    public Symbol findObjcSymbol(Symbol bestSymbol, long targetAddress, MachOModule module) {
        String className = null;
        Objc2Method objc2Method = null;
        boolean isClassMethod = false;
        for (Objc2Class clazz : classList) {
            for (Objc2Method method : clazz.methods) {
                if ( objc2Method == null ) {
                    if ( method.imp <= targetAddress ) {
                        className = clazz.name;
                        objc2Method = method;
                    }
                } else if ( (method.imp <= targetAddress) && (objc2Method.imp < method.imp) ) {
                    isClassMethod = false;
                    className = clazz.name;
                    objc2Method = method;
                }
            }
            if (clazz.metaClass != null) {
                for (Objc2Method method : clazz.metaClass.methods) {
                    if ( objc2Method == null ) {
                        if ( method.imp <= targetAddress ) {
                            isClassMethod = true;
                            className = clazz.name;
                            objc2Method = method;
                        }
                    } else if ( (method.imp <= targetAddress) && (objc2Method.imp < method.imp) ) {
                        isClassMethod = true;
                        className = clazz.name;
                        objc2Method = method;
                    }
                }
            }
        }
        for (Objc2Category category : categoryList) {
            for (Objc2Method method : category.instanceMethodList) {
                if ( objc2Method == null ) {
                    if ( method.imp <= targetAddress ) {
                        className = category.name;
                        objc2Method = method;
                    }
                } else if ( (method.imp <= targetAddress) && (objc2Method.imp < method.imp) ) {
                    isClassMethod = false;
                    className = category.name;
                    objc2Method = method;
                }
            }
            for (Objc2Method method : category.classMethodList) {
                if ( objc2Method == null ) {
                    if ( method.imp <= targetAddress ) {
                        isClassMethod = true;
                        className = category.name;
                        objc2Method = method;
                    }
                } else if ( (method.imp <= targetAddress) && (objc2Method.imp < method.imp) ) {
                    isClassMethod = true;
                    className = category.name;
                    objc2Method = method;
                }
            }
        }
        if (bestSymbol != null &&
                objc2Method != null &&
                (objc2Method.imp <= targetAddress) && (bestSymbol.getAddress() < module.base + objc2Method.imp)) {
            bestSymbol = null;
        }
        if (bestSymbol != null) {
            return bestSymbol;
        }
        if (objc2Method != null) {
            String symbolName = String.valueOf(isClassMethod ? '+' : '-') +
                    '[' + className + ' ' + objc2Method.name + ']';
            return new ExportSymbol(symbolName, module.base + objc2Method.imp, module, 0, com.github.unidbg.ios.MachO.EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE);
        }
        return null;
    }

    final void load() {
        loadClasses();
        loadCategories();
    }

    abstract void loadClasses();

    abstract void loadCategories();

}
