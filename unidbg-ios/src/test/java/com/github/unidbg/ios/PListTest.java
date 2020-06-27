package com.github.unidbg.ios;

import com.dd.plist.NSDictionary;
import com.dd.plist.PropertyListParser;
import junit.framework.TestCase;

import java.io.File;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class PListTest extends TestCase {

    public void testPList() throws Exception {
        Map<String, Object> map = new HashMap<>();
        map.put("AppleICUForce24HourTime", 1);
        map.put("AppleLanguages", new String[] { "zh-Hans", "en" });
        map.put("AppleLocale", "zh_CN");
        NSDictionary root = (NSDictionary) NSDictionary.fromJavaObject(map);
        PropertyListParser.saveAsBinary(root, new File("target/plist_test.plist"));
    }

    public void testLocale() {
        Locale locale = Locale.getDefault();
        System.out.println(locale);
        System.out.println(locale.getCountry());
        System.out.println(locale.getLanguage());
    }

}
