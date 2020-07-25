package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class FunctionType extends BaseNode {
    private final BaseNode returnType;
    private final BaseNode params;
    private final BaseNode cvQualifier;
    private final SimpleReferenceType referenceQualifier;
    private final BaseNode exceptionSpec;

    public FunctionType(BaseNode returnType, BaseNode params, BaseNode cvQualifier, SimpleReferenceType referenceQualifier, BaseNode exceptionSpec) {
        super(NodeType.FunctionType);
        this.returnType = returnType;
        this.params = params;
        this.cvQualifier = cvQualifier;
        this.referenceQualifier = referenceQualifier;
        this.exceptionSpec = exceptionSpec;
    }

    @Override
    public void printLeft(StringWriter writer) {
        returnType.printLeft(writer);
        writer.write(" ");
    }

    @Override
    public void printRight(StringWriter writer) {
        writer.write("(");
        params.print(writer);
        writer.write(")");

        returnType.printRight(writer);

        cvQualifier.print(writer);

        if (referenceQualifier.qualifier != Reference.None) {
            writer.write(" ");
            referenceQualifier.PrintQualifier(writer);
        }

        if (exceptionSpec != null) {
            writer.write(" ");
            exceptionSpec.print(writer);
        }
    }

    @Override
    public boolean hasRightPart() {
        return true;
    }

    @Override
    public boolean hasFunctions() {
        return true;
    }
}