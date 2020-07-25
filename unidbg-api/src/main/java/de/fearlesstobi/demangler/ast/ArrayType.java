package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class ArrayType extends BaseNode {
    private final BaseNode base;
    private BaseNode dimensionExpression;
    private String dimensionString;

    public ArrayType(BaseNode base) {
        super(NodeType.ArrayType);
        this.base = base;
        dimensionExpression = null;
    }

    public ArrayType(BaseNode base, BaseNode dimensionExpression) {
        super(NodeType.ArrayType);
        this.base = base;
        this.dimensionExpression = dimensionExpression;
    }

    public ArrayType(BaseNode base, String dimensionString) {
        super(NodeType.ArrayType);
        this.base = base;
        this.dimensionString = dimensionString;
    }

    @Override
    public boolean hasRightPart() {
        return true;
    }

    @Override
    public boolean isArray() {
        return true;
    }

    @Override
    public void printLeft(StringWriter writer) {
        base.printLeft(writer);
    }

    @Override
    public void printRight(StringWriter writer) {
        // FIXME: detect if previous char was a ].
        writer.write(" ");

        writer.write("[");

        if (dimensionString != null) {
            writer.write(dimensionString);
        } else if (dimensionExpression != null) {
            dimensionExpression.print(writer);
        }

        writer.write("]");

        base.printRight(writer);
    }
}