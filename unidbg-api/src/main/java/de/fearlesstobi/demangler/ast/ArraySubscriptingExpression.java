package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class ArraySubscriptingExpression extends BaseNode {
    private final BaseNode leftNode;
    private final BaseNode subscript;

    public ArraySubscriptingExpression(BaseNode leftNode, BaseNode subscript) {
        super(NodeType.ArraySubscriptingExpression);
        this.leftNode = leftNode;
        this.subscript = subscript;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("(");
        leftNode.print(writer);
        writer.write(")[");
        subscript.print(writer);
        writer.write("]");
    }
}