package com.ss.android.ugc.live;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import com.sun.jna.Pointer;

import cn.banny.unidbg.Emulator;
import cn.banny.unidbg.Module;
import cn.banny.unidbg.arm.ARMEmulator;
import cn.banny.unidbg.file.FileIO;
import cn.banny.unidbg.file.IOResolver;
import cn.banny.unidbg.linux.android.AndroidARMEmulator;
import cn.banny.unidbg.linux.android.AndroidResolver;
import cn.banny.unidbg.linux.android.dvm.AbstractJni;
import cn.banny.unidbg.linux.android.dvm.DalvikModule;
import cn.banny.unidbg.linux.android.dvm.DvmClass;
import cn.banny.unidbg.linux.android.dvm.VM;
import cn.banny.unidbg.linux.android.dvm.array.ByteArray;
import cn.banny.unidbg.memory.Memory;
import cn.banny.unidbg.pointer.UnicornPointer;
import cn.banny.unidbg.spi.SyscallNumHandler;
import unicorn.ArmConst;
import unicorn.Unicorn;

/**
 * @author bmax
 *
 */
public class HuoshanXGorgon extends AbstractJni implements IOResolver{

	private static final String APP_PACKAGE_NAME = "com.ss.android.ugc.live";
	private static final String APK_PATH = "src/test/resources/app/app_pcandroid_v6.6.0_5375327.apk";
	
    private static final Log log = LogFactory.getLog(HuoshanXGorgon.class);
    
	private ARMEmulator emulator;
	private VM vm;
	private Module module;
	
	private DvmClass jni_com_ss_secuni_b_c;
	private DvmClass jni_com_ss_android_common_applog_UserInfo;
	private DvmClass jni_com_ss_sys_ces_a;

	private void init() throws IOException {
		this.emulator = new AndroidARMEmulator(APP_PACKAGE_NAME);
		emulator.getSyscallHandler().addIOResolver(this);
		emulator.getSyscallHandler().addSyscallNumHandler(345, new SyscallNumHandler() {
			
			@Override
			public void handle(Unicorn u, Emulator emulator) {
				//log.warn(emulator.getPid());
				Pointer pCpu = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R0);
				Pointer pNode = UnicornPointer.register(emulator, ArmConst.UC_ARM_REG_R1);
				if(pCpu != null) {
					
				}
				if(pNode != null) {
					//log.warn("yyy");
				}
				//log.warn(pNode.toString());
				
			}
		});

		final Memory memory = emulator.getMemory();
		memory.setLibraryResolver(new AndroidResolver(19));
		
		vm = emulator.createDalvikVM(new File(APK_PATH));
		vm.setJni(this);
		DalvikModule dm = vm.loadLibrary("cms", false);
		dm.callJNI_OnLoad(emulator);
		module = dm.getModule();

		jni_com_ss_sys_ces_a = vm.resolveClass("com/ss/sys/ces/a");
	}
	
	private void uninit() throws IOException {
		emulator.close();
	}
	
	private String getXGorgonTest() throws IOException {
        String url = "https://hotsoon-hl.snssdk.com/hotsoon/item/profile/published_list/?to_user_id=MS4wLjABAAAAy3ecZublKZr5TpkBIzkOzZiEVLPjXL62yF0INXNHjcA&max_time=1561365310000&offset=0&count=20&req_from=feed_loadmore&ad_user_agent=com.ss.android.ugc.live%2F660%20%28Linux%3B%20U%3B%20Android%204.4.4%3B%20zh_CN%3B%20AOSP%20on%20HammerHead%3B%20Build%2FKTU84P%3B%20Chrome%29&feed_video_gap=0&live_sdk_version=660&iid=75903517949&device_id=67880212994&ac=wifi&channel=pcandroid&aid=1112&app_name=live_stream&version_code=660&version_name=6.6.0&device_platform=android&ssmix=a&device_type=AOSP%20on%20HammerHead&device_brand=Android&language=zh&os_api=19&os_version=4.4.4&uuid=352136069473441&openudid=e4e81b553666579e&manifest_version_code=660&resolution=1080*1776&dpi=480&update_version_code=6605&_rticket=1562047185225&jssdk_version=2.12.2.h6&ab_version=822321%2C949020%2C712302%2C862468%2C832457%2C689931%2C979720%2C945941%2C984451%2C928648%2C839334%2C692223%2C981933%2C889328%2C830471%2C662290%2C943434%2C557631%2C976862%2C947985%2C797936%2C988811%2C932075%2C661946%2C819013%2C911478%2C841997%2C980563%2C938228%2C705072%2C989200%2C929458%2C929431%2C682009%2C841787%2C841483%2C920238%2C971357%2C665355%2C922855%2C957619%2C848691%2C974188%2C949485%2C643980%2C829630%2C953568%2C985496%2C913503%2C975752%2C944207%2C894639%2C457535%2C937270%2C768602%2C956110%2C957249&client_version_code=660&new_nav=1&ws_status=CONNECTED&ts=1562047185";
        
        Map<String, String> headers = new HashMap<>();
        //headers.put("cookie", "odin_tt=5bba819eee4de3bc6f92ab181b25431320c181fd1eb5b10c949397d67147cc709a9f7c46f102f2c29915b10651a5cd9fd3328c0083ba26e5f12c7023a8567332; qh[360]=1; install_id=75903517949; ttreq=1$208ac7e7ccc53af49b6aea227b31e0bb4f68fc81");
        headers.put("cookie", "odin_tt=5bba819eee4de3bc6f92ab181b25431320c181fd1eb5b10c949397d67147cc709a9f7c46f102f2c29915b10651a5cd9fd3328c0083ba26e5f12c7023a8567332; install_id=75903517949; ttreq=1$208ac7e7ccc53af49b6aea227b31e0bb4f68fc81");
        
        //int timestamp = ((int)(System.currentTimeMillis() / 1000));
        int timestamp = 1562047185;
        log.info("gargon:" + getXGargon(url, timestamp, headers));
		return null;
	}
	
    // at com.ss.sys.ces.gg.tt   public static void init_gorgon()
    private String getXGargon(String url, int timestamp, Map<String, String> headers ){
        if(url == null) return null;

        if(!url.toLowerCase().contains("http") && !url.toLowerCase().contains("https")) {
            throw new NullPointerException("nein http/https");
        }

        if((url.toLowerCase().contains("X-Khronos")) && (url.toLowerCase().contains("X-Gorgon"))) {
            throw new NullPointerException("it was");
        }

        if(HuoShanUtils.tt.filter_url(url)) {
            throw new NullPointerException("filter_1");
        }


        String cook_md5 = HuoShanUtils.tt.format_url(url);
        String url_md5 = null;
        if(cook_md5.length() > 0){
            url_md5 = HuoShanUtils.e.a(cook_md5);
        }

        String stub = null, cookie_md5 = null, session_id_md5 = null;
        for(Map.Entry<String, String> entry : headers.entrySet()){
            if(entry.getKey().toUpperCase().contains("X-SS-STUB")){
                stub = entry.getValue();
            }
            if(entry.getKey().toUpperCase().contains("COOKIE")){
                String cookie = entry.getValue();
                if(cookie != null && cookie.length() > 0 ){
                    cookie_md5 = HuoShanUtils.e.a(cookie);
                    String session_id = HuoShanUtils.tt.format_session_id(cookie);
                    if(session_id != null && session_id.length() > 0 ){
                        session_id_md5 = HuoShanUtils.e.a(session_id);
                    }
                }
            }
        }
        if(url_md5 == null){
            url_md5 = "00000000000000000000000000000000";
        }
        if(stub == null){
            stub = "00000000000000000000000000000000";
        }
        if(cookie_md5 == null){
            cookie_md5 = "00000000000000000000000000000000";
        }
        if(session_id_md5 == null){
            session_id_md5 = "00000000000000000000000000000000";
        }
        String paramIn = url_md5 + stub + cookie_md5 + session_id_md5;
        //byte[] bytes = a.leviathan(timestamp, HuoShanUtils.hexStringToByteArray(paramIn));
        
        Number retNumber = jni_com_ss_sys_ces_a.callStaticJniMethod(emulator, "leviathan(I[B)[B", 
        		timestamp,
        		vm.addLocalObject(new ByteArray(HuoShanUtils.hexStringToByteArray(paramIn))));
        
        long hash = retNumber.intValue() & 0xffffffffL;
        ByteArray obj = vm.getObject(hash);
        byte[] bytes = obj.getValue();
        vm.deleteLocalRefs();
        return HuoShanUtils.bytesToHex(bytes);
    }

	
	public static void main(String[] args) throws IOException {
        //Logger.getLogger("cn.banny.unidbg.AbstractEmulator").setLevel(Level.ALL);
        //Logger.getLogger("cn.banny.unidbg.linux.android.dvm.DalvikVM").setLevel(Level.ALL);
        //Logger.getLogger("cn.banny.unidbg.linux.android.dvm.DalvikModule").setLevel(Level.ALL);
		HuoshanXGorgon xgorgon = new HuoshanXGorgon();
		xgorgon.init();
		
		long startTime=System.currentTimeMillis();   //获取开始时间  

		
		for(int i = 0; i < 3; i ++) {
			xgorgon.getXGorgonTest();
		}
		
		long endTime=System.currentTimeMillis(); //获取结束时间  
		System.out.println("total use "+(endTime - startTime)+" ms");   
		
		
		xgorgon.uninit();
	}
	
	
	
	@Override
	public FileIO resolve(File workDir, String pathname, int oflags) {
		// TODO Auto-generated method stub
		return null;
	}

}
