package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class EnclosedExpression extends BaseNode {
    private final String prefix;
    private final BaseNode expression;
    private final String postfix;

    public EnclosedExpression(String prefix, BaseNode expression, String postfix) {
        super(NodeType.EnclosedExpression);
        this.prefix = prefix;
        this.expression = expression;
        this.postfix = postfix;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write(prefix);
        expression.print(writer);
        writer.write(postfix);
    }
}