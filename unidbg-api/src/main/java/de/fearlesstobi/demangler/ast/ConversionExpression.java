package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class ConversionExpression extends BaseNode {
    private final BaseNode typeNode;
    private final BaseNode expressions;

    public ConversionExpression(BaseNode typeNode, BaseNode expressions) {
        super(NodeType.ConversionExpression);
        this.typeNode = typeNode;
        this.expressions = expressions;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("(");
        typeNode.print(writer);
        writer.write(")(");
        expressions.print(writer);
    }
}