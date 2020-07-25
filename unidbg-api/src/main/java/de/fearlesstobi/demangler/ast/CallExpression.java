package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;
import java.util.List;

import static de.fearlesstobi.demangler.util.StringUtil.nodeListToArray;

public class CallExpression extends NodeArray {
    private final BaseNode callee;

    public CallExpression(BaseNode callee, List<BaseNode> nodes) {
        super(nodes, NodeType.CallExpression);
        this.callee = callee;
    }

    @Override
    public void printLeft(StringWriter writer) {
        callee.print(writer);

        writer.write("(");

        writer.write(String.join(", ", nodeListToArray(nodes)));
        writer.write(")");
    }
}