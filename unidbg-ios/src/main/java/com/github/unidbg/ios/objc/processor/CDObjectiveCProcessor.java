package com.github.unidbg.ios.objc.processor;

import com.github.unidbg.Emulator;
import com.github.unidbg.Symbol;
import com.github.unidbg.ios.ExportSymbol;
import com.github.unidbg.ios.MachOModule;
import com.github.unidbg.ios.objc.ObjectiveCProcessor;
import io.kaitai.MachO;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public abstract class CDObjectiveCProcessor implements ObjectiveCProcessor {

    final Emulator<?> emulator;
    final MachOModule module;
    final Map<String, MachO.SegmentCommand64.Section64> objcSections;
    final List<ObjcClass> classList = new ArrayList<>();
    final List<Objc2Category> categoryList = new ArrayList<>();

    CDObjectiveCProcessor(Emulator<?> emulator, MachOModule module) {
        super();

        this.emulator = emulator;
        this.module = module;
        this.objcSections = module.objcSections;
    }

    @Override
    public Symbol findObjcSymbol(Symbol bestSymbol, long targetAddress, MachOModule module) {
        String className = null;
        ObjcMethod objc2Method = null;
        boolean isClassMethod = false;
        for (ObjcClass clazz : classList) {
            for (ObjcMethod method : clazz.getMethods()) {
                if ( objc2Method == null ) {
                    if ( method.getImp() <= targetAddress ) {
                        className = clazz.getName();
                        objc2Method = method;
                    }
                } else if ( (method.getImp() <= targetAddress) && (objc2Method.getImp() < method.getImp()) ) {
                    isClassMethod = false;
                    className = clazz.getName();
                    objc2Method = method;
                }
            }
            ObjcClass metaClass = clazz.getMeta();
            if (metaClass != null) {
                for (ObjcMethod method : metaClass.getMethods()) {
                    if ( objc2Method == null ) {
                        if ( method.getImp() <= targetAddress ) {
                            isClassMethod = true;
                            className = clazz.getName();
                            objc2Method = method;
                        }
                    } else if ( (method.getImp() <= targetAddress) && (objc2Method.getImp() < method.getImp()) ) {
                        isClassMethod = true;
                        className = clazz.getName();
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
                } else if ( (method.imp <= targetAddress) && (objc2Method.getImp() < method.imp) ) {
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
                } else if ( (method.imp <= targetAddress) && (objc2Method.getImp() < method.imp) ) {
                    isClassMethod = true;
                    className = category.name;
                    objc2Method = method;
                }
            }
        }
        if (bestSymbol != null && objc2Method != null && bestSymbol.getAddress() < module.base + objc2Method.getImp()) {
            bestSymbol = null;
        }
        if (bestSymbol != null) {
            return bestSymbol;
        }
        if (objc2Method != null) {
            String symbolName = String.valueOf(isClassMethod ? '+' : '-') +
                    '[' + className + ' ' + objc2Method.getName() + ']';
            return new ExportSymbol(symbolName, module.base + objc2Method.getImp(), module, 0, com.github.unidbg.ios.MachO.EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE);
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
