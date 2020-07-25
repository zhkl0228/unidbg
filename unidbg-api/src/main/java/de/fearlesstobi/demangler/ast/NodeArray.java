package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;
import java.util.List;

import static de.fearlesstobi.demangler.util.StringUtil.nodeListToArray;

public class NodeArray extends BaseNode {
    public final List<BaseNode> nodes;

    public NodeArray(List<BaseNode> nodes) {
        super(NodeType.NodeArray);
        this.nodes = nodes;
    }

    public NodeArray(List<BaseNode> nodes, NodeType type) {
        super(type);
        this.nodes = nodes;
    }

    @Override
    public boolean isArray() {
        return true;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write(String.join(", ", nodeListToArray(nodes)));
    }
}