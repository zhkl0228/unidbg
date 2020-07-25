package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class BracedRangeExpression extends BaseNode {
    private final BaseNode firstNode;
    private final BaseNode lastNode;
    private final BaseNode expression;

    public BracedRangeExpression(BaseNode firstNode, BaseNode lastNode, BaseNode expression) {
        super(NodeType.BracedRangeExpression);
        this.firstNode = firstNode;
        this.lastNode = lastNode;
        this.expression = expression;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("[");
        firstNode.print(writer);
        writer.write(" ... ");
        lastNode.print(writer);
        writer.write("]");

        writer.write(" = ");

        expression.print(writer);
    }
}
