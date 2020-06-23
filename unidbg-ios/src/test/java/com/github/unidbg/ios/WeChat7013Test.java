package com.github.unidbg.ios;

import com.github.unidbg.ios.ipa.IpaLoader;
import com.github.unidbg.ios.ipa.IpaLoader64;
import com.github.unidbg.ios.objc.ObjC;
import com.github.unidbg.ios.struct.objc.ObjcClass;
import com.github.unidbg.ios.struct.objc.ObjcObject;

import java.io.File;

public class WeChat7013Test extends WeChatTest {

    public static void main(String[] args) throws Exception {
        new WeChat7013Test().test();
    }

    @Override
    protected IpaLoader createLoader(File rootDir) {
        return new IpaLoader64(new File("../wechat/src/test/resources/app/com.tencent.xin_7.0.13.ipa"), rootDir);
    }

    @Override
    protected ObjcObject getMMServiceCenter(ObjC objc, ObjcClass cMMServiceCenter) {
        ObjcClass cMMContext = objc.getClass("MMContext");
        ObjcObject context = cMMContext.callObjc("currentContext");
        return context.callObjc("serviceCenter");
    }

}
