package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class NewExpression extends BaseNode {
    private final NodeArray expressions;
    private final BaseNode typeNode;
    private final NodeArray initializers;

    private final boolean isGlobal;
    private final boolean isArrayExpression;

    public NewExpression(NodeArray expressions, BaseNode typeNode, NodeArray initializers, boolean isGlobal, boolean isArrayExpression) {
        super(NodeType.NewExpression);
        this.expressions = expressions;
        this.typeNode = typeNode;
        this.initializers = initializers;

        this.isGlobal = isGlobal;
        this.isArrayExpression = isArrayExpression;
    }

    @Override
    public void printLeft(StringWriter writer) {
        if (isGlobal) {
            writer.write("::operator ");
        }

        writer.write("new ");

        if (isArrayExpression) {
            writer.write("[] ");
        }

        if (!expressions.nodes.isEmpty()) {
            writer.write("(");
            expressions.print(writer);
            writer.write(")");
        }

        typeNode.print(writer);

        if (!initializers.nodes.isEmpty()) {
            writer.write("(");
            initializers.print(writer);
            writer.write(")");
        }
    }
}