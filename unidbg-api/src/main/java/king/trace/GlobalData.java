package king.trace;

import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.util.*;

public class GlobalData {
    //上一次汇编指令
    public static String pre_codestr;
    //上一次汇编的第一个寄存器名称
    public static String pre_regname;
    //是否有记录上一次的数据
    public static boolean has_pre;
    //监控的地址
    public static Map<Integer,String> watch_address=new HashMap<Integer,String>();
    //监控地址打印的内存数据长度
    public static int watch_print_size=0x20;
    //计算结果和汇编的分隔符
    public static String print_split="-----";
    //忽略的module
    public static List<String> ignoreModuleList=new ArrayList<>();
    //忽略打印计算数据的操作指令
    public static List<String> ignoreOpList=new ArrayList<>();
    //是否要dump汇编的ldr指令的内存
    public static boolean is_dump_ldr=false;
    //是否要dump汇编的str指令的内存
    public static boolean is_dump_str=false;
    //dump汇编的ldr指令内存的大小
    public static int dump_ldr_size=0x30;
    //dump汇编的str指令内存的大小
    public static int dump_str_size=0x30;

    //arm64的对应寄存器，需要打印的就追加
    public static Map<String, Integer> arm64_reg_names ;
    static {
        Map<String,Integer > aMap =new HashMap<String, Integer>();
        aMap.put("X0", Arm64Const.UC_ARM64_REG_X0);
        aMap.put("X1", Arm64Const.UC_ARM64_REG_X1);
        aMap.put("X2", Arm64Const.UC_ARM64_REG_X2);
        aMap.put("X3", Arm64Const.UC_ARM64_REG_X3);
        aMap.put("X4", Arm64Const.UC_ARM64_REG_X4);
        aMap.put("X5", Arm64Const.UC_ARM64_REG_X5);
        aMap.put("X6", Arm64Const.UC_ARM64_REG_X6);
        aMap.put("X7", Arm64Const.UC_ARM64_REG_X7);
        aMap.put("X8", Arm64Const.UC_ARM64_REG_X8);
        aMap.put("X9", Arm64Const.UC_ARM64_REG_X9);
        aMap.put("X10", Arm64Const.UC_ARM64_REG_X10);
        aMap.put("X11", Arm64Const.UC_ARM64_REG_X11);
        aMap.put("X12", Arm64Const.UC_ARM64_REG_X12);
        aMap.put("X13", Arm64Const.UC_ARM64_REG_X13);
        aMap.put("X14", Arm64Const.UC_ARM64_REG_X14);
        aMap.put("X15", Arm64Const.UC_ARM64_REG_X15);
        aMap.put("X16", Arm64Const.UC_ARM64_REG_X16);
        aMap.put("X17", Arm64Const.UC_ARM64_REG_X17);
        aMap.put("X18", Arm64Const.UC_ARM64_REG_X18);
        aMap.put("X19", Arm64Const.UC_ARM64_REG_X19);
        aMap.put("X20", Arm64Const.UC_ARM64_REG_X20);
        aMap.put("X21", Arm64Const.UC_ARM64_REG_X21);
        aMap.put("X22", Arm64Const.UC_ARM64_REG_X22);
        aMap.put("X23", Arm64Const.UC_ARM64_REG_X23);
        aMap.put("X24", Arm64Const.UC_ARM64_REG_X24);
        aMap.put("X25", Arm64Const.UC_ARM64_REG_X25);
        aMap.put("X26", Arm64Const.UC_ARM64_REG_X26);
        aMap.put("X27", Arm64Const.UC_ARM64_REG_X27);
        aMap.put("X28", Arm64Const.UC_ARM64_REG_X28);
        aMap.put("X29", Arm64Const.UC_ARM64_REG_X29);
        aMap.put("X30", Arm64Const.UC_ARM64_REG_X30);
        aMap.put("W0", Arm64Const.UC_ARM64_REG_W0);
        aMap.put("W1", Arm64Const.UC_ARM64_REG_W1);
        aMap.put("W2", Arm64Const.UC_ARM64_REG_W2);
        aMap.put("W3", Arm64Const.UC_ARM64_REG_W3);
        aMap.put("W4", Arm64Const.UC_ARM64_REG_W4);
        aMap.put("W5", Arm64Const.UC_ARM64_REG_W5);
        aMap.put("W6", Arm64Const.UC_ARM64_REG_W6);
        aMap.put("W7", Arm64Const.UC_ARM64_REG_W7);
        aMap.put("W8", Arm64Const.UC_ARM64_REG_W8);
        aMap.put("W9", Arm64Const.UC_ARM64_REG_W9);
        aMap.put("W10", Arm64Const.UC_ARM64_REG_W10);
        aMap.put("W11", Arm64Const.UC_ARM64_REG_W11);
        aMap.put("W12", Arm64Const.UC_ARM64_REG_W12);
        aMap.put("W13", Arm64Const.UC_ARM64_REG_W13);
        aMap.put("W14", Arm64Const.UC_ARM64_REG_W14);
        aMap.put("W15", Arm64Const.UC_ARM64_REG_W15);
        aMap.put("W16", Arm64Const.UC_ARM64_REG_W16);
        aMap.put("W17", Arm64Const.UC_ARM64_REG_W17);
        aMap.put("W18", Arm64Const.UC_ARM64_REG_W18);
        aMap.put("W19", Arm64Const.UC_ARM64_REG_W19);
        aMap.put("W20", Arm64Const.UC_ARM64_REG_W20);
        aMap.put("W21", Arm64Const.UC_ARM64_REG_W21);
        aMap.put("W22", Arm64Const.UC_ARM64_REG_W22);
        aMap.put("W23", Arm64Const.UC_ARM64_REG_W23);
        aMap.put("W24", Arm64Const.UC_ARM64_REG_W24);
        aMap.put("W25", Arm64Const.UC_ARM64_REG_W25);
        aMap.put("W26", Arm64Const.UC_ARM64_REG_W26);
        aMap.put("W27", Arm64Const.UC_ARM64_REG_W27);
        aMap.put("W28", Arm64Const.UC_ARM64_REG_W28);
        aMap.put("W29", Arm64Const.UC_ARM64_REG_W29);
        aMap.put("W30", Arm64Const.UC_ARM64_REG_W30);
        aMap.put("SP", Arm64Const.UC_ARM64_REG_SP);
        aMap.put("XZR", Arm64Const.UC_ARM64_REG_XZR);
        aMap.put("WZR", Arm64Const.UC_ARM64_REG_WZR);
        aMap.put("IP", Arm64Const.UC_ARM64_REG_IP0);
        aMap.put("PC", Arm64Const.UC_ARM64_REG_PC);
        arm64_reg_names = Collections.unmodifiableMap(aMap);
    }
    //arm的对应寄存器
    public static Map<String, Integer> arm_reg_names ;
    static {
        Map<String,Integer > aMap =new HashMap<String, Integer>();
        aMap.put("R0", ArmConst.UC_ARM_REG_R0);
        aMap.put("R1", ArmConst.UC_ARM_REG_R1);
        aMap.put("R2", ArmConst.UC_ARM_REG_R2);
        aMap.put("R3", ArmConst.UC_ARM_REG_R3);
        aMap.put("R4", ArmConst.UC_ARM_REG_R4);
        aMap.put("R5", ArmConst.UC_ARM_REG_R5);
        aMap.put("R6", ArmConst.UC_ARM_REG_R6);
        aMap.put("R7", ArmConst.UC_ARM_REG_R7);
        aMap.put("R8", ArmConst.UC_ARM_REG_R8);
        aMap.put("R9", ArmConst.UC_ARM_REG_R9);
        aMap.put("R10", ArmConst.UC_ARM_REG_R10);
        aMap.put("R11", ArmConst.UC_ARM_REG_R11);
        aMap.put("R12", ArmConst.UC_ARM_REG_R12);
        aMap.put("R13", ArmConst.UC_ARM_REG_R13);
        aMap.put("R14", ArmConst.UC_ARM_REG_R14);
        aMap.put("R15", ArmConst.UC_ARM_REG_R15);
        aMap.put("SP", ArmConst.UC_ARM_REG_SP);
        aMap.put("IP", ArmConst.UC_ARM_REG_IP);
        aMap.put("PC", ArmConst.UC_ARM_REG_PC);
        arm_reg_names = Collections.unmodifiableMap(aMap);
    }
//    {
//        "X0": unicorn.arm64_const.UC_ARM64_REG_X0,
//                "X1": unicorn.arm64_const.UC_ARM64_REG_X1,
//                "X2": unicorn.arm64_const.UC_ARM64_REG_X2,
//                "X3": unicorn.arm64_const.UC_ARM64_REG_X3,
//                "X4": unicorn.arm64_const.UC_ARM64_REG_X4,
//                "X5": unicorn.arm64_const.UC_ARM64_REG_X5,
//                "X6": unicorn.arm64_const.UC_ARM64_REG_X6,
//                "X7": unicorn.arm64_const.UC_ARM64_REG_X7,
//                "X8": unicorn.arm64_const.UC_ARM64_REG_X8,
//                "X9": unicorn.arm64_const.UC_ARM64_REG_X9,
//                "X10": unicorn.arm64_const.UC_ARM64_REG_X10,
//                "X11": unicorn.arm64_const.UC_ARM64_REG_X11,
//                "X12": unicorn.arm64_const.UC_ARM64_REG_X12,
//                "X13": unicorn.arm64_const.UC_ARM64_REG_X13,
//                "X14": unicorn.arm64_const.UC_ARM64_REG_X14,
//                "X15": unicorn.arm64_const.UC_ARM64_REG_X15,
//                "X16": unicorn.arm64_const.UC_ARM64_REG_X16,
//                "X17": unicorn.arm64_const.UC_ARM64_REG_X17,
//                "X18": unicorn.arm64_const.UC_ARM64_REG_X18,
//                "X19": unicorn.arm64_const.UC_ARM64_REG_X19,
//                "X20": unicorn.arm64_const.UC_ARM64_REG_X20,
//                "X21": unicorn.arm64_const.UC_ARM64_REG_X21,
//                "X22": unicorn.arm64_const.UC_ARM64_REG_X22,
//                "X23": unicorn.arm64_const.UC_ARM64_REG_X23,
//                "X24": unicorn.arm64_const.UC_ARM64_REG_X24,
//                "X25": unicorn.arm64_const.UC_ARM64_REG_X25,
//                "X26": unicorn.arm64_const.UC_ARM64_REG_X26,
//                "X27": unicorn.arm64_const.UC_ARM64_REG_X27,
//                "X28": unicorn.arm64_const.UC_ARM64_REG_X28,
//                "W0": unicorn.arm64_const.UC_ARM64_REG_W0,
//                "W1": unicorn.arm64_const.UC_ARM64_REG_W1,
//                "W2": unicorn.arm64_const.UC_ARM64_REG_W2,
//                "W3": unicorn.arm64_const.UC_ARM64_REG_W3,
//                "W4": unicorn.arm64_const.UC_ARM64_REG_W4,
//                "W5": unicorn.arm64_const.UC_ARM64_REG_W5,
//                "W6": unicorn.arm64_const.UC_ARM64_REG_W6,
//                "W7": unicorn.arm64_const.UC_ARM64_REG_W7,
//                "W8": unicorn.arm64_const.UC_ARM64_REG_W8,
//                "W9": unicorn.arm64_const.UC_ARM64_REG_W9,
//                "W10": unicorn.arm64_const.UC_ARM64_REG_W10,
//                "W11": unicorn.arm64_const.UC_ARM64_REG_W11,
//                "W12": unicorn.arm64_const.UC_ARM64_REG_W12,
//                "W13": unicorn.arm64_const.UC_ARM64_REG_W13,
//                "W14": unicorn.arm64_const.UC_ARM64_REG_W14,
//                "W15": unicorn.arm64_const.UC_ARM64_REG_W15,
//                "W16": unicorn.arm64_const.UC_ARM64_REG_W16,
//                "W17": unicorn.arm64_const.UC_ARM64_REG_W17,
//                "W18": unicorn.arm64_const.UC_ARM64_REG_W18,
//                "W19": unicorn.arm64_const.UC_ARM64_REG_W19,
//                "W20": unicorn.arm64_const.UC_ARM64_REG_W20,
//                "W21": unicorn.arm64_const.UC_ARM64_REG_W21,
//                "W22": unicorn.arm64_const.UC_ARM64_REG_W22,
//                "W23": unicorn.arm64_const.UC_ARM64_REG_W23,
//                "W24": unicorn.arm64_const.UC_ARM64_REG_W24,
//                "W25": unicorn.arm64_const.UC_ARM64_REG_W25,
//                "W26": unicorn.arm64_const.UC_ARM64_REG_W26,
//                "W27": unicorn.arm64_const.UC_ARM64_REG_W27,
//                "W28": unicorn.arm64_const.UC_ARM64_REG_W28,
//                "SP": unicorn.arm64_const.UC_ARM64_REG_SP,
//    }
}
