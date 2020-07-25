package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class CastExpression extends BaseNode {
    private final String kind;
    private final BaseNode to;
    private final BaseNode from;

    public CastExpression(String kind, BaseNode to, BaseNode from) {
        super(NodeType.CastExpression);
        this.kind = kind;
        this.to = to;
        this.from = from;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write(kind);
        writer.write("<");
        to.printLeft(writer);
        writer.write(">(");
        from.printLeft(writer);
        writer.write(")");
    }
}