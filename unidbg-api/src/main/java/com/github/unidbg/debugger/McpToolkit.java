package com.github.unidbg.debugger;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

public class McpToolkit implements DebugRunnable<Void> {

    private final Map<String, McpTool> tools = new LinkedHashMap<>();
    private String defaultToolName;

    public McpToolkit addTool(McpTool tool) {
        if (defaultToolName == null) {
            defaultToolName = tool.name();
        }
        tools.put(tool.name(), tool);
        return this;
    }

    public McpToolkit setDefaultTool(String name) {
        if (!tools.containsKey(name)) {
            throw new IllegalArgumentException("Tool not found: " + name);
        }
        this.defaultToolName = name;
        return this;
    }

    public void run(Debugger debugger) throws Exception {
        for (McpTool tool : tools.values()) {
            debugger.addMcpTool(tool.name(), tool.description(), tool.paramNames());
        }
        debugger.run(this);
    }

    @Override
    public Void runWithArgs(String[] args) throws Exception {
        String toolName = args != null ? args[0] : null;
        if (toolName == null) {
            toolName = defaultToolName;
        }
        McpTool tool = toolName != null ? tools.get(toolName) : null;
        if (tool != null) {
            String[] params = args != null && args.length > 1 ? Arrays.copyOfRange(args, 1, args.length) : new String[0];
            tool.execute(params);
        }
        return null;
    }

}
