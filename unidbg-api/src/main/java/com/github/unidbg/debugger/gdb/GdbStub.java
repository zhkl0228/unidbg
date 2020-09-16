package com.github.unidbg.debugger.gdb;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.debugger.AbstractDebugServer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import unicorn.Arm64Const;
import unicorn.ArmConst;

import java.nio.ByteBuffer;
import java.util.*;

/**
 * GdbStub class
 * @author Humberto Silva Naves
 */
public final class GdbStub extends AbstractDebugServer {

    private static final Log log = LogFactory.getLog(GdbStub.class);

    static final String SIGTRAP = "05"; /* Trace trap (POSIX).  */

    final int[] registers;

    private String lastPacket;
    private final StringBuilder currentInputPacket;
    private int packetChecksum, packetFinished;

    public GdbStub(Emulator<?> emulator) {
        super(emulator);

        currentInputPacket = new StringBuilder();

        if (emulator.is32Bit()) { // arm32
            registers = new int[] {
                    ArmConst.UC_ARM_REG_R0,
                    ArmConst.UC_ARM_REG_R1,
                    ArmConst.UC_ARM_REG_R2,
                    ArmConst.UC_ARM_REG_R3,
                    ArmConst.UC_ARM_REG_R4,
                    ArmConst.UC_ARM_REG_R5,
                    ArmConst.UC_ARM_REG_R6,
                    ArmConst.UC_ARM_REG_R7,
                    ArmConst.UC_ARM_REG_R8,
                    ArmConst.UC_ARM_REG_R9,
                    ArmConst.UC_ARM_REG_R10,
                    ArmConst.UC_ARM_REG_R11,
                    ArmConst.UC_ARM_REG_R12,
                    ArmConst.UC_ARM_REG_SP,
                    ArmConst.UC_ARM_REG_LR,
                    ArmConst.UC_ARM_REG_PC,
                    ArmConst.UC_ARM_REG_CPSR
            };
        } else { // arm64
            registers = new int[34];
            for (int i = 0; i <= 28; i++) {
                registers[i] = Arm64Const.UC_ARM64_REG_X0 + i;
            }
            registers[29] = Arm64Const.UC_ARM64_REG_X29;
            registers[30] = Arm64Const.UC_ARM64_REG_X30;
            registers[31] = Arm64Const.UC_ARM64_REG_SP;
            registers[32] = Arm64Const.UC_ARM64_REG_PC;
            registers[33] = Arm64Const.UC_ARM64_REG_NZCV;
        }
    }

    @Override
    protected void onServerStart() {
        List<Module> loaded = new ArrayList<>(emulator.getMemory().getLoadedModules());
        Collections.sort(loaded, new Comparator<Module>() {
            @Override
            public int compare(Module o1, Module o2) {
                return (int) (o1.base - o2.base);
            }
        });
        for (Module module : loaded) {
            System.err.println("[0x" + Long.toHexString(module.base) + "]" + module.name);
        }
    }

    final void send(String packet) {
        sendData(packet.getBytes());
    }

    private void sendPacket(String packet) {
        lastPacket = packet;
        send(packet);
    }

    final void makePacketAndSend(String data) {
        if (log.isDebugEnabled()) {
            log.debug("makePacketAndSend: " + data);
        }

        int checksum = 0;
        data = escapePacketData(data);
        StringBuilder sb = new StringBuilder();
        sb.append("+");
        sb.append("$");
        for(int i = 0; i < data.length(); i++) {
            sb.append(data.charAt(i));
            checksum += (byte) data.charAt(i);
        }
        sb.append("#");
        sb.append(String.format("%02x", checksum & 0xff));
        sendPacket(sb.toString());
    }

    private String escapePacketData(String data) {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < data.length(); i++) {
            char c = data.charAt(i);
            if (c == '$' || c == '#' || c == '}') {
                sb.append("}");
                sb.append(c ^ 0x20);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    @Override
    protected void processInput(ByteBuffer input) {
        input.flip();

        while(input.hasRemaining()) {
            char c = (char) input.get();
            if (currentInputPacket.length() == 0) {
                switch (c) {
                    case '-':
                        reTransmitLastPacket();
                        break;
                    case '+': // Silently discard '+' packets
                        break;
                    case 0x3: // Ctrl-C requests
                        setSingleStep(1);
                        break;
                    case '$':
                        currentInputPacket.append(c);
                        packetChecksum = 0;
                        packetFinished = 0;
                        break;
                    default:
                        requestRetransmit();
                        break;

                }
            } else {
                currentInputPacket.append(c);
                if (packetFinished > 0) {
                    if (++packetFinished == 3) {
                        if (checkPacket()) {
                            processCommand(currentInputPacket.substring(1, currentInputPacket.length() - 3));
                        } else {
                            requestRetransmit();
                        }
                        currentInputPacket.setLength(0);
                    }
                } else if (c == '#') {
                    packetFinished = 1;
                } else {
                    packetChecksum += c;
                }
            }
        }

        input.clear();
    }

    private void requestRetransmit() {
        send("-");
    }

    private void reTransmitLastPacket() {
        send(lastPacket);
    }

    private boolean checkPacket() {
        try {
            int checksum = Integer.parseInt(currentInputPacket.substring(currentInputPacket.length() - 2), 16);
            return checksum == (packetChecksum & 0xff);
        } catch(NumberFormatException ex) {
            if (log.isDebugEnabled()) {
                log.debug("checkPacket currentInputPacket=" + currentInputPacket, ex);
            }
            return false;
        }
    }

    private void processCommand(String command) {
        for(String prefix : commands.keySet()) {
            if (command.startsWith(prefix)) {
                GdbStubCommand cmd = commands.get(prefix);
                if (log.isDebugEnabled()) {
                    log.debug("processCommand command=" + command + ", cmd=" + cmd);
                }
                if (cmd.processCommand(emulator, this, command)) {
                    return;
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.warn("Unsupported command=" + command);
        }
        makePacketAndSend("");
    }

    @Override
    protected void onHitBreakPoint(Emulator<?> emulator, long address) {
        if (isDebuggerConnected()) {
            makePacketAndSend("S" + SIGTRAP);
        }
    }

    @Override
    protected boolean onDebuggerExit() {
        makePacketAndSend("W00");
        return true;
    }

    @Override
    protected void onDebuggerConnected() {
    }

    private static final Map<String, GdbStubCommand> commands;

    static {
        commands = new HashMap<>();
        GdbStubCommand commandContinue = new ContinueCommand();
        commands.put("c", commandContinue);

        GdbStubCommand commandStep = new StepCommand();
        commands.put("s", commandStep);

        GdbStubCommand commandBreakpoint = new BreakpointCommand();
        commands.put("z0", commandBreakpoint);
        commands.put("Z0", commandBreakpoint);

        GdbStubCommand commandMemory = new MemoryCommand();
        commands.put("m", commandMemory);
        commands.put("M", commandMemory);

        GdbStubCommand commandRegisters = new RegistersCommand();
        commands.put("g", commandRegisters);
        commands.put("G", commandRegisters);

        GdbStubCommand commandRegister = new RegisterCommand();
        commands.put("p", commandRegister);
        commands.put("P", commandRegister);

        GdbStubCommand commandKill = new KillCommand();
        commands.put("k", commandKill);

        GdbStubCommand commandEnableExtendedMode = new EnableExtendedModeCommand();
        commands.put("!", commandEnableExtendedMode);

        GdbStubCommand commandLastSignal = new LastSignalCommand();
        commands.put("?", commandLastSignal);

        GdbStubCommand commandDetach = new DetachCommand();
        commands.put("D", commandDetach);

        GdbStubCommand commandQuery = new QueryCommand();
        commands.put("q", commandQuery);

        GdbStubCommand commandSetThread = new SetThreadCommand();
        commands.put("H", commandSetThread);

        GdbStubCommand commandVCont = new ExtendedCommand();
        commands.put("vCont", commandVCont);
    }

    @Override
    public String toString() {
        return "gdb";
    }
}