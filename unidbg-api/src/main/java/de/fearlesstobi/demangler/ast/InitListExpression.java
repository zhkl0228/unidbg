package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;
import java.util.List;

import static de.fearlesstobi.demangler.util.StringUtil.nodeListToArray;

public class InitListExpression extends BaseNode {
    private final BaseNode typeNode;
    private final List<BaseNode> nodes;

    public InitListExpression(BaseNode typeNode, List<BaseNode> nodes) {
        super(NodeType.InitListExpression);
        this.typeNode = typeNode;
        this.nodes = nodes;
    }

    @Override
    public void printLeft(StringWriter writer) {
        if (typeNode != null) {
            typeNode.print(writer);
        }

        writer.write("{");

        writer.write(String.join(", ", nodeListToArray(nodes)));

        writer.write("}");
    }
}