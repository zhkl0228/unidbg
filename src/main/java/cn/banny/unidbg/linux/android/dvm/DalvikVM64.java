package cn.banny.unidbg.linux.android.dvm;

import cn.banny.auxiliary.Inspector;
import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.arm.context.Arm64RegisterContext;
import cn.banny.unidbg.arm.Arm64Svc;
import cn.banny.unidbg.arm.context.RegisterContext;
import cn.banny.unidbg.memory.MemoryBlock;
import cn.banny.unidbg.memory.SvcMemory;
import cn.banny.unidbg.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import net.dongliu.apk.parser.ApkFile;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class DalvikVM64 extends BaseVM implements VM {

    private static final Log log = LogFactory.getLog(DalvikVM64.class);

    private final UnicornPointer _JavaVM;
    private final UnicornPointer _JNIEnv;

    public DalvikVM64(Emulator emulator, File apkFile) {
        super(emulator, apkFile);

        final SvcMemory svcMemory = emulator.getSvcMemory();
        _JavaVM = svcMemory.allocate(emulator.getPointerSize(), "_JavaVM");

        Pointer _FindClass = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                Arm64RegisterContext context = emulator.getContext();
                Pointer env = context.getXPointer(0);
                Pointer className = context.getXPointer(1);
                String name = className.getString(0);
                DvmClass dvmClass = resolveClass(name);
                long hash = dvmClass.hashCode() & 0xffffffffL;
                if (log.isDebugEnabled()) {
                    log.debug("FindClass env=" + env + ", className=" + name + ", hash=0x" + Long.toHexString(hash));
                }
                return hash;
            }
        });

        Pointer _Throw = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                DvmObject dvmObject = getObject(object.peer);
                log.warn("Throw object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getObjectType());
                jthrowable = dvmObject;
                return 0;
            }
        });

        Pointer _ExceptionOccurred = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionOccurred");
                }
                return jthrowable == null ? JNI_NULL : (jthrowable.hashCode() & 0xffffffffL);
            }
        });

        Pointer _ExceptionClear = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionClear");
                }
                jthrowable = null;
                return 0;
            }
        });

        Pointer _PushLocalFrame = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                int capacity = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("PushLocalFrame capacity=" + capacity);
                }
                return JNI_OK;
            }
        });

        Pointer _PopLocalFrame = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer jresult = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                if (log.isDebugEnabled()) {
                    log.debug("PopLocalFrame jresult=" + jresult);
                }
                return jresult == null ? 0 : jresult.peer;
            }
        });

        Pointer _NewGlobalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                if (object == null) {
                    return 0;
                }
                DvmObject dvmObject = getObject(object.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewGlobalRef object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getClass());
                }
                addObject(dvmObject, true);
                return object.peer;
            }
        });

        Pointer _DeleteGlobalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                if (log.isDebugEnabled()) {
                    log.debug("DeleteGlobalRef object=" + object);
                }
                globalObjectMap.remove(object.toUIntPeer());
                return 0;
            }
        });

        Pointer _DeleteLocalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                if (log.isDebugEnabled()) {
                    log.debug("DeleteLocalRef object=" + object);
                }
                localObjectMap.remove(object.toUIntPeer());
                return 0;
            }
        });

        Pointer _IsSameObject = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                Pointer ref1 = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer ref2 = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("IsSameObject ref1=" + ref1 + ", ref2=" + ref2);
                }
                return ref1 == ref2 || ref1.equals(ref2) ? JNI_TRUE : JNI_FALSE;
            }
        });

        Pointer _NewLocalRef = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                DvmObject dvmObject = getObject(object.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewLocalRef object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getClass());
                }
                return object.peer;
            }
        });

        Pointer _EnsureLocalCapacity = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                int capacity = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("EnsureLocalCapacity capacity=" + capacity);
                }
                return 0;
            }
        });

        Pointer _NewObject = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectV clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", lr=" + UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.newObject(ArmVarArg.create(emulator, DalvikVM64.this));
                }
            }
        });

        Pointer _NewObjectV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnicornPointer va_list = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectV clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.newObjectV(new VaList(DalvikVM64.this, va_list));
                }
            }
        });

        Pointer _GetObjectClass = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                DvmObject dvmObject = getObject(object.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectClass object=" + object + ", dvmObject=" + dvmObject);
                }
                if (dvmObject == null) {
                    throw new UnicornException();
                } else {
                    DvmClass dvmClass = dvmObject.objectType;
                    return dvmClass.hashCode();
                }
            }
        });

        Pointer _IsInstanceOf = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                DvmObject dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("IsInstanceOf object=" + object + ", clazz=" + clazz + ", dvmObject=" + dvmObject + ", dvmClass=" + dvmClass);
                }
                if (dvmObject == null || dvmClass == null) {
                    throw new UnicornException();
                }
                return dvmObject.isInstanceOf(DalvikVM64.this, dvmClass) ? JNI_TRUE : JNI_FALSE;
            }
        });

        Pointer _GetMethodID = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer methodName = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                Pointer argsPointer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                String name = methodName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetMethodID class=" + clazz + ", methodName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                if (dvmClass == null) {
                    throw new UnicornException();
                } else {
                    return dvmClass.getMethodID(name, args);
                }
            }
        });

        Pointer _CallObjectMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return addObject(dvmMethod.callObjectMethod(dvmObject, ArmVarArg.create(emulator, DalvikVM64.this)), false);
                }
            }
        });

        Pointer _CallObjectMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnicornPointer va_list = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                DvmObject dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException("dvmObject=" + dvmObject + ", dvmClass=" + dvmClass + ", jmethodID=" + jmethodID);
                } else {
                    return addObject(dvmMethod.callObjectMethodV(dvmObject, new VaList(DalvikVM64.this, va_list)), false);
                }
            }
        });

        Pointer _CallBooleanMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.callBooleanMethod(dvmObject, ArmVarArg.create(emulator, DalvikVM64.this));
                }
            }
        });

        Pointer _CallBooleanMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnicornPointer va_list = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.callBooleanMethodV(dvmObject, new VaList(DalvikVM64.this, va_list));
                }
            }
        });

        Pointer _CallIntMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.callIntMethod(dvmObject, ArmVarArg.create(emulator, DalvikVM64.this));
                }
            }
        });

        Pointer _CallIntMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnicornPointer va_list = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.callIntMethodV(dvmObject, new VaList(DalvikVM64.this, va_list));
                }
            }
        });

        Pointer _CallVoidMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    dvmMethod.callVoidMethod(dvmObject, ArmVarArg.create(emulator, DalvikVM64.this));
                    return 0;
                }
            }
        });

        Pointer _CallVoidMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnicornPointer va_list = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    dvmMethod.callVoidMethodV(dvmObject, new VaList(DalvikVM64.this, va_list));
                    return 0;
                }
            }
        });

        Pointer _GetFieldID = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer fieldName = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                Pointer argsPointer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                String name = fieldName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetFieldID class=" + clazz + ", fieldName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                if (dvmClass == null) {
                    throw new UnicornException();
                } else {
                    return dvmClass.getFieldID(name, args);
                }
            }
        });

        Pointer _GetObjectField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    return dvmField.getObjectField(dvmObject);
                }
            }
        });

        Pointer _GetBooleanField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetBooleanField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    return dvmField.getBooleanField(dvmObject);
                }
            }
        });

        Pointer _GetIntField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetIntField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    return dvmField.getIntField(dvmObject);
                }
            }
        });

        Pointer _GetLongField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetLongField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.peer);
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    return dvmField.getLongField(dvmObject);
                }
            }
        });

        Pointer _SetObjectField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnicornPointer value = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("SetObjectField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    dvmField.setObjectField(dvmObject, getObject(value.toUIntPeer()));
                }
                return 0;
            }
        });

        Pointer _SetBooleanField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                int value = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("SetBooleanField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    dvmField.setBooleanField(dvmObject, value == JNI_TRUE);
                }
                return 0;
            }
        });

        Pointer _SetIntField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                int value = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("SetIntField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    dvmField.setIntField(dvmObject, value);
                }
                return 0;
            }
        });

        Pointer _SetLongField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                long value = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X3)).longValue();
                if (log.isDebugEnabled()) {
                    log.debug("SetLongField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject dvmObject = getObject(object.toUIntPeer());
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    dvmField.setLongField(dvmObject, value);
                }
                return 0;
            }
        });

        Pointer _SetDoubleField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                RegisterContext context = emulator.getContext();
                UnicornPointer object = context.getPointerArg(1);
                UnicornPointer jfieldID = context.getPointerArg(2);
                ByteBuffer buffer = ByteBuffer.allocate(8);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                buffer.putLong(context.getLongArg(3));
                buffer.flip();
                double value = buffer.getDouble();
                if (log.isDebugEnabled()) {
                    log.debug("SetDoubleField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.peer);
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    dvmField.setDoubleField(dvmObject, value);
                }
                return 0;
            }
        });

        Pointer _GetStaticMethodID = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer methodName = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                Pointer argsPointer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                String name = methodName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticMethodID class=" + clazz + ", methodName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                if (dvmClass == null) {
                    throw new UnicornException();
                } else {
                    return dvmClass.getStaticMethodID(name, args);
                }
            }
        });

        Pointer _CallStaticObjectMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return addObject(dvmMethod.callStaticObjectMethod(ArmVarArg.create(emulator, DalvikVM64.this)), false);
                }
            }
        });

        Pointer _CallStaticObjectMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnicornPointer va_list = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return addObject(dvmMethod.callStaticObjectMethodV(new VaList(DalvikVM64.this, va_list)), false);
                }
            }
        });

        Pointer _CallStaticBooleanMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.CallStaticBooleanMethod(ArmVarArg.create(emulator, DalvikVM64.this));
                }
            }
        });

        Pointer _CallStaticBooleanMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnicornPointer va_list = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.callStaticBooleanMethodV(new VaList(DalvikVM64.this, va_list));
                }
            }
        });

        Pointer _CallStaticIntMethod = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticIntMethodV clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.callStaticIntMethod(ArmVarArg.create(emulator, DalvikVM64.this));
                }
            }
        });

        Pointer _CallStaticIntMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnicornPointer va_list = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticIntMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.callStaticIntMethodV(new VaList(DalvikVM64.this, va_list));
                }
            }
        });

        Pointer _CallStaticLongMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnicornPointer va_list = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticLongMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    long value = dvmMethod.callStaticLongMethodV(new VaList(DalvikVM64.this, va_list));
                    emulator.getUnicorn().reg_write(Arm64Const.UC_ARM64_REG_X1, (int) (value >> 32));
                    return (value & 0xffffffffL);
                }
            }
        });

        Pointer _CallStaticVoidMethodV = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                UnicornPointer va_list = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticVoidMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.toUIntPeer());
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    dvmMethod.callStaticVoidMethodV(new VaList(DalvikVM64.this, va_list));
                    return 0;
                }
            }
        });

        Pointer _GetStaticFieldID = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer fieldName = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                Pointer argsPointer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X3);
                String name = fieldName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticFieldID class=" + clazz + ", fieldName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                if (dvmClass == null) {
                    throw new UnicornException();
                } else {
                    return dvmClass.getStaticFieldID(name, args);
                }
            }
        });

        Pointer _GetStaticObjectField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticObjectField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.staticFieldMap.get(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    return dvmField.getStaticObjectField();
                }
            }
        });

        Pointer _GetStaticIntField = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticIntField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                DvmField dvmField = dvmClass == null ? null : dvmClass.staticFieldMap.get(jfieldID.toUIntPeer());
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    return dvmField.getStaticIntField();
                }
            }
        });

        Pointer _GetStringUTFLength = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                DvmObject string = getObject(UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFLength string=" + string + ", lr=" + UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                String value = (String) string.getValue();
                byte[] data = value.getBytes(StandardCharsets.UTF_8);
                return data.length;
            }
        });

        Pointer _GetStringUTFChars = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                StringObject string = getObject(UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toUIntPeer());
                Pointer isCopy = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                String value = string.getValue();
                byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFChars string=" + string + ", isCopy=" + isCopy + ", value=" + value + ", lr=" + UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                byte[] data = Arrays.copyOf(bytes, bytes.length + 1);
                MemoryBlock memoryBlock = emulator.getMemory().malloc(data.length);
                memoryBlock.getPointer().write(0, data, 0, data.length);
                string.memoryBlock = memoryBlock;
                return memoryBlock.getPointer().toUIntPeer();
            }
        });

        Pointer _ReleaseStringUTFChars = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                StringObject string = getObject(UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toUIntPeer());
                Pointer pointer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseStringUTFChars string=" + string + ", pointer=" + pointer + ", lr=" + UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                if (string.memoryBlock != null && string.memoryBlock.isSame(pointer)) {
                    string.memoryBlock.free(true);
                    string.memoryBlock = null;
                }
                return 0;
            }
        });

        Pointer _GetArrayLength = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer pointer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Array array = getObject(pointer.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetArrayLength array=" + array);
                }
                return array.length();
            }
        });

        Pointer _GetObjectArrayElement = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                ArrayObject array = getObject(UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toUIntPeer());
                int index = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectArrayElement array=" + array + ", index=" + index);
                }
                return addObject(array.getValue()[index], false);
            }
        });

        Pointer _NewByteArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                int size = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("NewByteArray size=" + size);
                }
                return addObject(new ByteArray(new byte[size]), false);
            }
        });

        Pointer _NewIntArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                int size = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("NewIntArray size=" + size);
                }
                return addObject(new IntArray(new int[size]), false);
            }
        });

        Pointer _NewDoubleArray = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                int size = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("_NewDoubleArray size=" + size);
                }
                return addObject(new DoubleArray(new double[size]), false);
            }
        });

        Pointer _GetByteArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer arrayPointer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer isCopy = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("GetByteArrayElements arrayPointer=" + arrayPointer + ", isCopy=" + isCopy);
                }
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                ByteArray array = getObject(arrayPointer.toUIntPeer());
                byte[] value = array.value;
                MemoryBlock memoryBlock = emulator.getMemory().malloc(value.length);
                memoryBlock.getPointer().write(0, value, 0, value.length);
                array.memoryBlock = memoryBlock;
                return memoryBlock.getPointer().peer;
            }
        });

        Pointer _GetStringLength = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                DvmObject string = getObject(UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetStringLength string=" + string + ", lr=" + UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                String value = (String) string.getValue();
                return value.length();
            }
        });

        Pointer _GetStringChars = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                StringObject string = getObject(UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toUIntPeer());
                Pointer isCopy = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                String value = string.getValue();
                byte[] bytes = new byte[value.length() * 2];
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                for (char c : value.toCharArray()) {
                    buffer.putChar(c);
                }
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFChars string=" + string + ", isCopy=" + isCopy + ", value=" + value + ", lr=" + UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                byte[] data = Arrays.copyOf(bytes, bytes.length + 1);
                MemoryBlock memoryBlock = emulator.getMemory().malloc(data.length);
                memoryBlock.getPointer().write(0, data, 0, data.length);
                string.memoryBlock = memoryBlock;
                return memoryBlock.getPointer().peer;
            }
        });

        Pointer _ReleaseStringChars = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                StringObject string = getObject(UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toUIntPeer());
                Pointer pointer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseStringChars string=" + string + ", pointer=" + pointer + ", lr=" + UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR));
                }
                if (string.memoryBlock != null && string.memoryBlock.isSame(pointer)) {
                    string.memoryBlock.free(true);
                    string.memoryBlock = null;
                }
                return 0;
            }
        });

        Pointer _NewStringUTF = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                Pointer bytes = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                String string = bytes.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("NewStringUTF bytes=" + bytes + ", string=" + string);
                }
                return addObject(new StringObject(DalvikVM64.this, string), false);
            }
        });

        Pointer _ReleaseByteArrayElements = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer arrayPointer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer pointer = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                int mode = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseByteArrayElements arrayPointer=" + arrayPointer + ", pointer=" + pointer + ", mode=" + mode);
                }
                ByteArray array = getObject(arrayPointer.toUIntPeer());
                switch (mode) {
                    case JNI_COMMIT:
                        array.setValue(pointer.getByteArray(0, array.value.length));
                        break;
                    case 0:
                        array.setValue(pointer.getByteArray(0, array.value.length));
                    case JNI_ABORT:
                        if (array.memoryBlock != null && array.memoryBlock.isSame(pointer)) {
                            array.memoryBlock.free(true);
                            array.memoryBlock = null;
                        }
                        break;
                }
                return 0;
            }
        });

        Pointer _GetByteArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                ByteArray array = getObject(UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toUIntPeer());
                int start = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
                int length = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
                Pointer buf = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X4);
                byte[] data = Arrays.copyOfRange(array.value, start, start + length);
                if (log.isDebugEnabled()) {
                    Inspector.inspect(data, "GetByteArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _SetByteArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                ByteArray array = getObject(UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toUIntPeer());
                int start = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
                int len = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
                Pointer buf = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X4);
                byte[] data = buf.getByteArray(0, len);
                if (log.isDebugEnabled()) {
                    Inspector.inspect(data, "SetByteArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                }
                array.setData(start, data);
                return 0;
            }
        });

        Pointer _SetIntArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                IntArray array = getObject(UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toUIntPeer());
                int start = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
                int len = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
                Pointer buf = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X4);
                int[] data = buf.getIntArray(0, len);
                if (log.isDebugEnabled()) {
                    log.debug("SetIntArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                }
                array.setData(start, data);
                return 0;
            }
        });

        Pointer _SetDoubleArrayRegion = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                DoubleArray array = getObject(UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).toUIntPeer());
                int start = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
                int len = ((Number) u.reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
                Pointer buf = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X4);
                double[] data = buf.getDoubleArray(0, len);
                if (log.isDebugEnabled()) {
                    log.debug("SetDoubleArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                }
                array.setData(start, data);
                return 0;
            }
        });

        Pointer _RegisterNatives = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer methods = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
                int nMethods = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X3)).intValue();
                DvmClass dvmClass = classMap.get(clazz.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("RegisterNatives dvmClass=" + dvmClass + ", methods=" + methods + ", nMethods=" + nMethods);
                }
                for (int i = 0; i < nMethods; i++) {
                    Pointer method = methods.share(i * emulator.getPointerSize() * 3);
                    Pointer name = method.getPointer(0);
                    Pointer signature = method.getPointer(emulator.getPointerSize());
                    Pointer fnPtr = method.getPointer(emulator.getPointerSize() * 2);
                    String methodName = name.getString(0);
                    String signatureValue = signature.getString(0);
                    if (log.isDebugEnabled()) {
                        log.debug("RegisterNatives dvmClass=" + dvmClass + ", name=" + methodName + ", signature=" + signatureValue + ", fnPtr=" + fnPtr);
                    }
                    dvmClass.nativesMap.put(methodName + signatureValue, (UnicornPointer) fnPtr);
                }
                return JNI_OK;
            }
        });

        Pointer _GetJavaVM = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer vm = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                if (log.isDebugEnabled()) {
                    log.debug("GetJavaVM vm=" + vm);
                }
                vm.setPointer(0, _JavaVM);
                return JNI_OK;
            }
        });

        Pointer _ExceptionCheck = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionCheck jthrowable=" + jthrowable);
                }
                return jthrowable == null ? JNI_FALSE : JNI_TRUE;
            }
        });

        Pointer _GetObjectRefType = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                DvmObject dvmGlobalObject = globalObjectMap.get(object.toUIntPeer());
                DvmObject dvmLocalObject = localObjectMap.get(object.toUIntPeer());
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectRefType object=" + object + ", dvmGlobalObject=" + dvmGlobalObject + ", dvmLocalObject=" + dvmLocalObject);
                }
                if (dvmGlobalObject != null) {
                    return JNIGlobalRefType;
                } else if(dvmLocalObject != null) {
                    return JNILocalRefType;
                } else {
                    return JNIInvalidRefType;
                }
            }
        });

        final UnicornPointer impl = svcMemory.allocate(0xE9 * emulator.getPointerSize(), "JNIEnv.impl");
        for (int i = 0; i < 0xE9 * emulator.getPointerSize(); i += emulator.getPointerSize()) {
            impl.setLong(i, i);
        }
        impl.setPointer(0x30, _FindClass);
        impl.setPointer(0x68, _Throw);
        impl.setPointer(0x78, _ExceptionOccurred);
        impl.setPointer(0x88, _ExceptionClear);
        impl.setPointer(0x98, _PushLocalFrame);
        impl.setPointer(0xA0, _PopLocalFrame);
        impl.setPointer(0xa8, _NewGlobalRef);
        impl.setPointer(0xB0, _DeleteGlobalRef);
        impl.setPointer(0xB8, _DeleteLocalRef);
        impl.setPointer(0xC0, _IsSameObject);
        impl.setPointer(0xC8, _NewLocalRef);
        impl.setPointer(0xd0, _EnsureLocalCapacity);
        impl.setPointer(0xE0, _NewObject);
        impl.setPointer(0xE8, _NewObjectV);
        impl.setPointer(0xF8, _GetObjectClass);
        impl.setPointer(0x100, _IsInstanceOf);
        impl.setPointer(0x108, _GetMethodID);
        impl.setPointer(0x110, _CallObjectMethod);
        impl.setPointer(0x118, _CallObjectMethodV);
        impl.setPointer(0x128, _CallBooleanMethod);
        impl.setPointer(0x130, _CallBooleanMethodV);
        impl.setPointer(0x188, _CallIntMethod);
        impl.setPointer(0x190, _CallIntMethodV);
        impl.setPointer(0x1e8, _CallVoidMethod);
        impl.setPointer(0x1f0, _CallVoidMethodV);
        impl.setPointer(0x2f0, _GetFieldID);
        impl.setPointer(0x2F8, _GetObjectField);
        impl.setPointer(0x300, _GetBooleanField);
        impl.setPointer(0x320, _GetIntField);
        impl.setPointer(0x328, _GetLongField);
        impl.setPointer(0x340, _SetObjectField);
        impl.setPointer(0x348, _SetBooleanField);
        impl.setPointer(0x368, _SetIntField);
        impl.setPointer(0x370, _SetLongField);
        impl.setPointer(0x380, _SetDoubleField);
        impl.setPointer(0x388, _GetStaticMethodID);
        impl.setPointer(0x390, _CallStaticObjectMethod);
        impl.setPointer(0x398, _CallStaticObjectMethodV);
        impl.setPointer(0x3A8, _CallStaticBooleanMethod);
        impl.setPointer(0x3B0, _CallStaticBooleanMethodV);
        impl.setPointer(0x408, _CallStaticIntMethod);
        impl.setPointer(0x410, _CallStaticIntMethodV);
        impl.setPointer(0x428, _CallStaticLongMethodV);
        impl.setPointer(0x470, _CallStaticVoidMethodV);
        impl.setPointer(0x480, _GetStaticFieldID);
        impl.setPointer(0x488, _GetStaticObjectField);
        impl.setPointer(0x4B0, _GetStaticIntField);
        impl.setPointer(0x540, _GetStringUTFLength);
        impl.setPointer(0x548, _GetStringUTFChars);
        impl.setPointer(0x550, _ReleaseStringUTFChars);
        impl.setPointer(0x558, _GetArrayLength);
        impl.setPointer(0x580, _NewByteArray);
        impl.setPointer(0x598, _NewIntArray);
        impl.setPointer(0x5b0, _NewDoubleArray);
        impl.setPointer(0x5c0, _GetByteArrayElements);
        impl.setPointer(0x520, _GetStringLength);
        impl.setPointer(0x528, _GetStringChars);
        impl.setPointer(0x530, _ReleaseStringChars);
        impl.setPointer(0x538, _NewStringUTF);
        impl.setPointer(0x568, _GetObjectArrayElement);
        impl.setPointer(0x600, _ReleaseByteArrayElements);
        impl.setPointer(0x640, _GetByteArrayRegion);
        impl.setPointer(0x680, _SetByteArrayRegion);
        impl.setPointer(0x698, _SetIntArrayRegion);
        impl.setPointer(0x6B0, _SetDoubleArrayRegion);
        impl.setPointer(0x6B8, _RegisterNatives);
        impl.setPointer(0x6D8, _GetJavaVM);
        impl.setPointer(0x720, _ExceptionCheck);
        impl.setPointer(0x740, _GetObjectRefType);

        _JNIEnv = svcMemory.allocate(emulator.getPointerSize(), "_JNIEnv");
        _JNIEnv.setPointer(0, impl);

        UnicornPointer _AttachCurrentThread = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                Pointer vm = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                Pointer env = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                Pointer args = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2); // JavaVMAttachArgs*
                if (log.isDebugEnabled()) {
                    log.debug("AttachCurrentThread vm=" + vm + ", env=" + env.getPointer(0) + ", args=" + args);
                }
                env.setPointer(0, _JNIEnv);
                return JNI_OK;
            }
        });

        UnicornPointer _GetEnv = svcMemory.registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator emulator) {
                Pointer vm = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
                Pointer env = UnicornPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
                int version = ((Number) emulator.getUnicorn().reg_read(Arm64Const.UC_ARM64_REG_X2)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("GetEnv vm=" + vm + ", env=" + env.getPointer(0) + ", version=0x" + Integer.toHexString(version));
                }
                env.setPointer(0, _JNIEnv);
                return JNI_OK;
            }
        });

        UnicornPointer _JNIInvokeInterface = svcMemory.allocate(emulator.getPointerSize() * 8, "_JNIInvokeInterface");
        for (int i = 0; i < emulator.getPointerSize() * 8; i += emulator.getPointerSize()) {
            _JNIInvokeInterface.setInt(i, i);
        }
        _JNIInvokeInterface.setPointer(emulator.getPointerSize() * 4, _AttachCurrentThread);
        _JNIInvokeInterface.setPointer(emulator.getPointerSize() * 6, _GetEnv);

        _JavaVM.setPointer(0, _JNIInvokeInterface);

        if (log.isDebugEnabled()) {
            log.debug("_JavaVM=" + _JavaVM + ", _JNIInvokeInterface=" + _JNIInvokeInterface + ", _JNIEnv=" + _JNIEnv);
        }
    }

    @Override
    public Pointer getJavaVM() {
        return _JavaVM;
    }

    @Override
    public Pointer getJNIEnv() {
        return _JNIEnv;
    }

    byte[] findLibrary(ApkFile apkFile, String soName) throws IOException {
        byte[] soData = apkFile.getFileData("lib/arm64-v8a/" + soName);
        if (soData != null) {
            log.debug("resolve arm64-v8a library: " + soName);
            return soData;
        } else {
            return null;
        }
    }
}
