package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class ConversionOperatorType extends ParentNode {
    public ConversionOperatorType(BaseNode child) {
        super(NodeType.ConversionOperatorType, child);
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("operator ");
        child.print(writer);
    }
}