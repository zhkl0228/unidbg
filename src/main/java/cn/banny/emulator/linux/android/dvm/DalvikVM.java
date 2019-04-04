package cn.banny.emulator.linux.android.dvm;

import cn.banny.auxiliary.Inspector;
import cn.banny.emulator.Emulator;
import cn.banny.emulator.arm.ArmSvc;
import cn.banny.emulator.memory.MemoryBlock;
import cn.banny.emulator.memory.SvcMemory;
import cn.banny.emulator.pointer.UnicornPointer;
import com.sun.jna.Pointer;
import net.dongliu.apk.parser.ApkFile;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.ArmConst;
import unicorn.Unicorn;
import unicorn.UnicornException;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class DalvikVM extends BaseVM implements VM {

    private static final Log log = LogFactory.getLog(DalvikVM.class);

    private final UnicornPointer _JavaVM;
    private final UnicornPointer _JNIEnv;

    public DalvikVM(Emulator emulator, File apkFile) {
        super(emulator, apkFile);

        final SvcMemory svcMemory = emulator.getSvcMemory();
        _JavaVM = svcMemory.allocate(emulator.getPointerSize());

        Pointer _FindClass = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                Pointer env = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer className = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                String name = className.getString(0);
                DvmClass dvmClass = resolveClass(name);
                long hash = dvmClass.hashCode() & 0xffffffffL;
                if (log.isDebugEnabled()) {
                    log.debug("FindClass env=" + env + ", className=" + name + ", hash=0x" + Long.toHexString(hash));
                }
                return (int) hash;
            }
        });

        Pointer _Throw = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                DvmObject dvmObject = getObject(object.peer);
                log.warn("Throw object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getObjectType());
                jthrowable = dvmObject;
                return 0;
            }
        });

        Pointer _ExceptionOccurred = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionOccurred");
                }
                return jthrowable == null ? JNI_NULL : (int) (jthrowable.hashCode() & 0xffffffffL);
            }
        });

        Pointer _ExceptionClear = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionClear");
                }
                jthrowable = null;
                return 0;
            }
        });

        Pointer _PushLocalFrame = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                int capacity = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("PushLocalFrame capacity=" + capacity);
                }
                return JNI_OK;
            }
        });

        Pointer _PopLocalFrame = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer jresult = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                if (log.isDebugEnabled()) {
                    log.debug("PopLocalFrame jresult=" + jresult);
                }
                return jresult == null ? 0 : (int) jresult.peer;
            }
        });

        Pointer _NewGlobalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                DvmObject dvmObject = getObject(object.peer);
                if (log.isDebugEnabled()) {
                    log.debug("NewGlobalRef object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getClass());
                }
                addObject(dvmObject, true);
                return (int) object.peer;
            }
        });

        Pointer _DeleteGlobalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                if (log.isDebugEnabled()) {
                    log.debug("DeleteGlobalRef object=" + object);
                }
                globalObjectMap.remove(object.peer);
                return 0;
            }
        });

        Pointer _DeleteLocalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                if (log.isDebugEnabled()) {
                    log.debug("DeleteLocalRef object=" + object);
                }
                localObjectMap.remove(object.peer);
                return 0;
            }
        });

        Pointer _IsSameObject = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                Pointer ref1 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer ref2 = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("IsSameObject ref1=" + ref1 + ", ref2=" + ref2);
                }
                return ref1 == ref2 || ref1.equals(ref2) ? JNI_TRUE : JNI_FALSE;
            }
        });

        Pointer _NewLocalRef = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                DvmObject dvmObject = getObject(object.peer);
                if (log.isDebugEnabled()) {
                    log.debug("NewLocalRef object=" + object + ", dvmObject=" + dvmObject + ", class=" + dvmObject.getClass());
                }
                return (int) object.peer;
            }
        });

        Pointer _NewObject = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectV clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.newObject(emulator);
                }
            }
        });

        Pointer _NewObjectV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (log.isDebugEnabled()) {
                    log.debug("NewObjectV clazz=" + dvmClass + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.newObjectV(new VaList(DalvikVM.this, va_list));
                }
            }
        });

        Pointer _GetObjectClass = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                DvmObject dvmObject = getObject(object.peer);
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

        Pointer _IsInstanceOf = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = classMap.get(clazz.peer);
                if (log.isDebugEnabled()) {
                    log.debug("IsInstanceOf object=" + object + ", clazz=" + clazz + ", dvmObject=" + dvmObject + ", dvmClass=" + dvmClass);
                }
                if (dvmObject == null || dvmClass == null) {
                    throw new UnicornException();
                }
                return dvmObject.isInstanceOf(DalvikVM.this, dvmClass) ? JNI_TRUE : JNI_FALSE;
            }
        });

        Pointer _GetMethodID = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer methodName = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                Pointer argsPointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                String name = methodName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetMethodID class=" + clazz + ", methodName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                if (dvmClass == null) {
                    throw new UnicornException();
                } else {
                    return dvmClass.getMethodID(name, args);
                }
            }
        });

        Pointer _CallObjectMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return addObject(dvmMethod.callObjectMethod(dvmObject, emulator), false);
                }
            }
        });

        Pointer _CallObjectMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallObjectMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException("dvmObject=" + dvmObject + ", dvmClass=" + dvmClass);
                } else {
                    return addObject(dvmMethod.callObjectMethodV(dvmObject, new VaList(DalvikVM.this, va_list)), false);
                }
            }
        });

        Pointer _CallBooleanMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallBooleanMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.callBooleanMethodV(dvmObject, new VaList(DalvikVM.this, va_list));
                }
            }
        });

        Pointer _CallIntMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.callIntMethod(dvmObject, emulator);
                }
            }
        });

        Pointer _CallIntMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallIntMethodV object=" + object + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.callIntMethodV(dvmObject, new VaList(DalvikVM.this, va_list));
                }
            }
        });

        Pointer _CallVoidMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallVoidMethod object=" + object + ", jmethodID=" + jmethodID);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.methodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    dvmMethod.callVoidMethod(dvmObject, emulator);
                    return 0;
                }
            }
        });

        Pointer _GetFieldID = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer fieldName = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                Pointer argsPointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                String name = fieldName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetFieldID class=" + clazz + ", fieldName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                if (dvmClass == null) {
                    throw new UnicornException();
                } else {
                    return dvmClass.getFieldID(name, args);
                }
            }
        });

        Pointer _GetObjectField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.peer);
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    return dvmField.getObjectField(dvmObject);
                }
            }
        });

        Pointer _GetBooleanField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetBooleanField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.peer);
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    return dvmField.getBooleanField(dvmObject);
                }
            }
        });

        Pointer _GetIntField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetIntField object=" + object + ", jfieldID=" + jfieldID);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.peer);
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    return dvmField.getIntField(dvmObject);
                }
            }
        });

        Pointer _SetObjectField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer value = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("SetObjectField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.peer);
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    dvmField.setObjectField(dvmObject, getObject(value.peer));
                }
                return 0;
            }
        });

        Pointer _SetBooleanField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                int value = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("SetBooleanField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.peer);
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    dvmField.setBooleanField(dvmObject, value == JNI_TRUE);
                }
                return 0;
            }
        });

        Pointer _SetIntField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                int value = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("SetIntField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.peer);
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    dvmField.setIntField(dvmObject, value);
                }
                return 0;
            }
        });

        Pointer _SetLongField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer sp = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP);
                long value = sp.getLong(0);
                // emulator.attach().debug(emulator);
                if (log.isDebugEnabled()) {
                    log.debug("SetLongField object=" + object + ", jfieldID=" + jfieldID + ", value=" + value);
                }
                DvmObject dvmObject = getObject(object.peer);
                DvmClass dvmClass = dvmObject == null ? null : dvmObject.objectType;
                DvmField dvmField = dvmClass == null ? null : dvmClass.fieldMap.get(jfieldID.peer);
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    dvmField.setLongField(dvmObject, value);
                }
                return 0;
            }
        });

        Pointer _GetStaticMethodID = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer methodName = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                Pointer argsPointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                String name = methodName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticMethodID class=" + clazz + ", methodName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                if (dvmClass == null) {
                    throw new UnicornException();
                } else {
                    return dvmClass.getStaticMethodID(name, args);
                }
            }
        });

        Pointer _CallStaticObjectMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethod clazz=" + clazz + ", jmethodID=" + jmethodID);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return addObject(dvmMethod.callStaticObjectMethod(emulator), false);
                }
            }
        });

        Pointer _CallStaticObjectMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticObjectMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return addObject(dvmMethod.callStaticObjectMethodV(new VaList(DalvikVM.this, va_list)), false);
                }
            }
        });

        Pointer _CallStaticBooleanMethod = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethod clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.CallStaticBooleanMethod(emulator);
                }
            }
        });

        Pointer _CallStaticBooleanMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticBooleanMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.callStaticBooleanMethodV();
                }
            }
        });

        Pointer _CallStaticIntMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticIntMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    return dvmMethod.callStaticIntMethodV(new VaList(DalvikVM.this, va_list));
                }
            }
        });

        Pointer _CallStaticLongMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticLongMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    long value = dvmMethod.callStaticLongMethodV(new VaList(DalvikVM.this, va_list));
                    emulator.getUnicorn().reg_write(ArmConst.UC_ARM_REG_R1, (int) (value >> 32));
                    return (int) (value & 0xffffffffL);
                }
            }
        });

        Pointer _CallStaticVoidMethodV = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jmethodID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                UnicornPointer va_list = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                if (log.isDebugEnabled()) {
                    log.debug("CallStaticVoidMethodV clazz=" + clazz + ", jmethodID=" + jmethodID + ", va_list=" + va_list);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmMethod dvmMethod = dvmClass == null ? null : dvmClass.staticMethodMap.get(jmethodID.peer);
                if (dvmMethod == null) {
                    throw new UnicornException();
                } else {
                    dvmMethod.callStaticVoidMethodV(new VaList(DalvikVM.this, va_list));
                    return 0;
                }
            }
        });

        Pointer _GetStaticFieldID = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer fieldName = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                Pointer argsPointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R3);
                String name = fieldName.getString(0);
                String args = argsPointer.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticFieldID class=" + clazz + ", fieldName=" + name + ", args=" + args);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                if (dvmClass == null) {
                    throw new UnicornException();
                } else {
                    return dvmClass.getStaticFieldID(name, args);
                }
            }
        });

        Pointer _GetStaticObjectField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticObjectField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmField dvmField = dvmClass == null ? null : dvmClass.staticFieldMap.get(jfieldID.peer);
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    return dvmField.getStaticObjectField();
                }
            }
        });

        Pointer _GetStaticIntField = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                UnicornPointer jfieldID = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetStaticIntField clazz=" + clazz + ", jfieldID=" + jfieldID);
                }
                DvmClass dvmClass = classMap.get(clazz.peer);
                DvmField dvmField = dvmClass == null ? null : dvmClass.staticFieldMap.get(jfieldID.peer);
                if (dvmField == null) {
                    throw new UnicornException();
                } else {
                    return dvmField.getStaticIntField();
                }
            }
        });

        Pointer _GetStringUTFLength = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                DvmObject string = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).peer);
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFLength string=" + string + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                String value = (String) string.getValue();
                byte[] data = value.getBytes(StandardCharsets.UTF_8);
                return data.length;
            }
        });

        Pointer _GetStringUTFChars = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                StringObject string = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).peer);
                Pointer isCopy = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                String value = string.getValue();
                byte[] data = value.getBytes(StandardCharsets.UTF_8);
                if (log.isDebugEnabled()) {
                    log.debug("GetStringUTFChars string=" + string + ", isCopy=" + isCopy + ", value=" + value + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                MemoryBlock memoryBlock = emulator.getMemory().malloc(data.length);
                memoryBlock.getPointer().write(0, data, 0, data.length);
                string.memoryBlock = memoryBlock;
                return (int) memoryBlock.getPointer().peer;
            }
        });

        Pointer _ReleaseStringUTFChars = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                StringObject string = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).peer);
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseStringUTFChars string=" + string + ", pointer=" + pointer + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                if (string.memoryBlock != null && string.memoryBlock.isSame(pointer)) {
                    string.memoryBlock.free();
                    string.memoryBlock = null;
                }
                return 0;
            }
        });

        Pointer _GetArrayLength = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Array array = getObject(pointer.peer);
                if (log.isDebugEnabled()) {
                    log.debug("GetArrayLength array=" + array + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                return array.length();
            }
        });

        Pointer _GetObjectArrayElement = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                ArrayObject array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).peer);
                int index = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectArrayElement array=" + array + ", index=" + index);
                }
                return addObject(array.getValue()[index], false);
            }
        });

        Pointer _NewByteArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                int size = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("NewByteArray size=" + size);
                }
                return addObject(new ByteArray(new byte[size]), false);
            }
        });

        Pointer _NewIntArray = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                int size = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R1)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("NewIntArray size=" + size);
                }
                return addObject(new IntArray(new int[size]), false);
            }
        });

        Pointer _GetByteArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                ByteArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).peer);
                Pointer isCopy = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("GetByteArrayElements array=" + array + ", isCopy=" + isCopy);
                }
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                byte[] value = array.value;
                MemoryBlock memoryBlock = emulator.getMemory().malloc(value.length);
                memoryBlock.getPointer().write(0, value, 0, value.length);
                array.memoryBlock = memoryBlock;
                return (int) memoryBlock.getPointer().peer;
            }
        });

        Pointer _GetStringLength = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                DvmObject string = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).peer);
                if (log.isDebugEnabled()) {
                    log.debug("GetStringLength string=" + string + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                String value = (String) string.getValue();
                return value.length();
            }
        });

        Pointer _GetStringChars = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                StringObject string = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).peer);
                Pointer isCopy = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (isCopy != null) {
                    isCopy.setInt(0, JNI_TRUE);
                }
                String value = string.getValue();
                byte[] data = new byte[value.length() * 2];
                ByteBuffer buffer = ByteBuffer.wrap(data);
                buffer.order(ByteOrder.LITTLE_ENDIAN);
                for (char c : value.toCharArray()) {
                    buffer.putChar(c);
                }
                if (log.isDebugEnabled()) {
                    log.debug("GetStringChars string=" + string + ", isCopy=" + isCopy + ", value=" + value + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                MemoryBlock memoryBlock = emulator.getMemory().malloc(data.length);
                memoryBlock.getPointer().write(0, data, 0, data.length);
                string.memoryBlock = memoryBlock;
                return (int) memoryBlock.getPointer().peer;
            }
        });

        Pointer _ReleaseStringChars = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                StringObject string = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).peer);
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseStringChars string=" + string + ", pointer=" + pointer + ", lr=" + UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_LR));
                }
                if (string.memoryBlock != null && string.memoryBlock.isSame(pointer)) {
                    string.memoryBlock.free();
                    string.memoryBlock = null;
                }
                return 0;
            }
        });

        Pointer _NewStringUTF = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                Pointer bytes = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                String string = bytes.getString(0);
                if (log.isDebugEnabled()) {
                    log.debug("NewStringUTF bytes=" + bytes + ", string=" + string);
                }
                return addObject(new StringObject(DalvikVM.this, string), false);
            }
        });

        Pointer _ReleaseByteArrayElements = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                ByteArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).peer);
                Pointer pointer = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                int mode = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("ReleaseByteArrayElements array=" + array + ", pointer=" + pointer + ", mode=" + mode);
                }
                switch (mode) {
                    case JNI_COMMIT:
                        array.setValue(pointer.getByteArray(0, array.value.length));
                        break;
                    case 0:
                        array.setValue(pointer.getByteArray(0, array.value.length));
                    case JNI_ABORT:
                        if (array.memoryBlock != null && array.memoryBlock.isSame(pointer)) {
                            array.memoryBlock.free();
                            array.memoryBlock = null;
                        }
                        break;
                }
                return 0;
            }
        });

        Pointer _GetByteArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                ByteArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).peer);
                int start = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                int length = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP).getPointer(0);
                byte[] data = Arrays.copyOfRange(array.value, start, start + length);
                if (log.isDebugEnabled()) {
                    Inspector.inspect(data, "GetByteArrayRegion array=" + array + ", start=" + start + ", length=" + length + ", buf=" + buf);
                }
                buf.write(0, data, 0, data.length);
                return 0;
            }
        });

        Pointer _SetByteArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                ByteArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).peer);
                int start = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                int len = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP).getPointer(0);
                byte[] data = buf.getByteArray(0, len);
                if (log.isDebugEnabled()) {
                    Inspector.inspect(data, "SetByteArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                }
                array.setData(start, data);
                return 0;
            }
        });

        Pointer _SetIntArrayRegion = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                IntArray array = getObject(UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1).peer);
                int start = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                int len = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                Pointer buf = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_SP).getPointer(0);
                int[] data = buf.getIntArray(0, len);
                if (log.isDebugEnabled()) {
                    log.debug("SetIntArrayRegion array=" + array + ", start=" + start + ", len=" + len + ", buf=" + buf);
                }
                array.setData(start, data);
                return 0;
            }
        });

        Pointer _RegisterNatives = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                Unicorn u = emulator.getUnicorn();
                UnicornPointer clazz = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer methods = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2);
                int nMethods = ((Number) u.reg_read(ArmConst.UC_ARM_REG_R3)).intValue();
                DvmClass dvmClass = classMap.get(clazz.peer);
                if (log.isDebugEnabled()) {
                    log.debug("RegisterNatives dvmClass=" + dvmClass + ", methods=" + methods + ", nMethods=" + nMethods);
                }
                for (int i = 0; i < nMethods; i++) {
                    Pointer method = methods.share(i * 0xc);
                    Pointer name = method.getPointer(0);
                    Pointer signature = method.getPointer(4);
                    Pointer fnPtr = method.getPointer(8);
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

        Pointer _GetJavaVM = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer vm = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                if (log.isDebugEnabled()) {
                    log.debug("GetJavaVM vm=" + vm);
                }
                vm.setPointer(0, _JavaVM);
                return JNI_OK;
            }
        });

        Pointer _ExceptionCheck = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                if (log.isDebugEnabled()) {
                    log.debug("ExceptionCheck jthrowable=" + jthrowable);
                }
                return jthrowable == null ? JNI_FALSE : JNI_TRUE;
            }
        });

        Pointer _GetObjectRefType = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                UnicornPointer object = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                DvmObject dvmObject = globalObjectMap.get(object.peer);
                DvmClass dvmClass = classMap.get(object.peer);
                if (log.isDebugEnabled()) {
                    log.debug("GetObjectRefType object=" + object + ", dvmObject=" + dvmObject + ", dvmClass=" + dvmClass);
                }
                if (dvmClass == null) {
                    return JNIInvalidRefType;
                }
                if (dvmObject != null) {
                    return JNIGlobalRefType;
                } else {
                    dvmObject = localObjectMap.get(object.peer);
                }
                return dvmObject == null ? JNIInvalidRefType : JNILocalRefType;
            }
        });

        final UnicornPointer impl = svcMemory.allocate(0x3a4 + emulator.getPointerSize());
        for (int i = 0; i < 0x3a4; i += 4) {
            impl.setInt(i, i);
        }
        impl.setPointer(0x18, _FindClass);
        impl.setPointer(0x34, _Throw);
        impl.setPointer(0x3c, _ExceptionOccurred);
        impl.setPointer(0x44, _ExceptionClear);
        impl.setPointer(0x4c, _PushLocalFrame);
        impl.setPointer(0x50, _PopLocalFrame);
        impl.setPointer(0x54, _NewGlobalRef);
        impl.setPointer(0x58, _DeleteGlobalRef);
        impl.setPointer(0x5C, _DeleteLocalRef);
        impl.setPointer(0x60, _IsSameObject);
        impl.setPointer(0x64, _NewLocalRef);
        impl.setPointer(0x70, _NewObject);
        impl.setPointer(0x74, _NewObjectV);
        impl.setPointer(0x7c, _GetObjectClass);
        impl.setPointer(0x80, _IsInstanceOf);
        impl.setPointer(0x84, _GetMethodID);
        impl.setPointer(0x88, _CallObjectMethod);
        impl.setPointer(0x8c, _CallObjectMethodV);
        impl.setPointer(0x98, _CallBooleanMethodV);
        impl.setPointer(0xc4, _CallIntMethod);
        impl.setPointer(0xc8, _CallIntMethodV);
        impl.setPointer(0xf4, _CallVoidMethod);
        impl.setPointer(0x178, _GetFieldID);
        impl.setPointer(0x17c, _GetObjectField);
        impl.setPointer(0x180, _GetBooleanField);
        impl.setPointer(0x190, _GetIntField);
        impl.setPointer(0x1a0, _SetObjectField);
        impl.setPointer(0x1a4, _SetBooleanField);
        impl.setPointer(0x1b4, _SetIntField);
        impl.setPointer(0x1b8, _SetLongField);
        impl.setPointer(0x1c4, _GetStaticMethodID);
        impl.setPointer(0x1c8, _CallStaticObjectMethod);
        impl.setPointer(0x1cc, _CallStaticObjectMethodV);
        impl.setPointer(0x1d4, _CallStaticBooleanMethod);
        impl.setPointer(0x1d8, _CallStaticBooleanMethodV);
        impl.setPointer(0x208, _CallStaticIntMethodV);
        impl.setPointer(0x214, _CallStaticLongMethodV);
        impl.setPointer(0x238, _CallStaticVoidMethodV);
        impl.setPointer(0x240, _GetStaticFieldID);
        impl.setPointer(0x244, _GetStaticObjectField);
        impl.setPointer(0x258, _GetStaticIntField);
        impl.setPointer(0x2a0, _GetStringUTFLength);
        impl.setPointer(0x2a4, _GetStringUTFChars);
        impl.setPointer(0x2a8, _ReleaseStringUTFChars);
        impl.setPointer(0x2ac, _GetArrayLength);
        impl.setPointer(0x2c0, _NewByteArray);
        impl.setPointer(0x2cc, _NewIntArray);
        impl.setPointer(0x2e0, _GetByteArrayElements);
        impl.setPointer(0x290, _GetStringLength);
        impl.setPointer(0x294, _GetStringChars);
        impl.setPointer(0x298, _ReleaseStringChars);
        impl.setPointer(0x29c, _NewStringUTF);
        impl.setPointer(0x2b4, _GetObjectArrayElement);
        impl.setPointer(0x300, _ReleaseByteArrayElements);
        impl.setPointer(0x320, _GetByteArrayRegion);
        impl.setPointer(0x340, _SetByteArrayRegion);
        impl.setPointer(0x34c, _SetIntArrayRegion);
        impl.setPointer(0x35c, _RegisterNatives);
        impl.setPointer(0x36c, _GetJavaVM);
        impl.setPointer(0x390, _ExceptionCheck);
        impl.setPointer(0x3a0, _GetObjectRefType);

        _JNIEnv = svcMemory.allocate(emulator.getPointerSize());
        _JNIEnv.setPointer(0, impl);

        UnicornPointer _AttachCurrentThread = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                Pointer vm = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer env = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                Pointer args = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R2); // JavaVMAttachArgs*
                if (log.isDebugEnabled()) {
                    log.debug("AttachCurrentThread vm=" + vm + ", env=" + env.getPointer(0) + ", args=" + args);
                }
                env.setPointer(0, _JNIEnv);
                return JNI_OK;
            }
        });

        UnicornPointer _GetEnv = svcMemory.registerSvc(new ArmSvc() {
            @Override
            public int handle(Emulator emulator) {
                Pointer vm = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
                Pointer env = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
                int version = ((Number) emulator.getUnicorn().reg_read(ArmConst.UC_ARM_REG_R2)).intValue();
                if (log.isDebugEnabled()) {
                    log.debug("GetEnv vm=" + vm + ", env=" + env.getPointer(0) + ", version=0x" + Integer.toHexString(version));
                }
                env.setPointer(0, _JNIEnv);
                return JNI_OK;
            }
        });

        UnicornPointer _JNIInvokeInterface = svcMemory.allocate(emulator.getPointerSize() * 8);
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
        byte[] soData = apkFile.getFileData("lib/armeabi-v7a/" + soName);
        if (soData != null) {
            log.debug("resolve armeabi-v7a library: " + soName);
            return soData;
        }
        soData = apkFile.getFileData("lib/armeabi/" + soName);
        if (soData != null) {
            log.debug("resolve armeabi library: " + soName);
        }
        return soData;
    }
}
