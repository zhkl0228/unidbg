package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class FunctionParameter extends BaseNode {
    private final String number;

    public FunctionParameter(String number) {
        super(NodeType.FunctionParameter);
        this.number = number;
    }

    @Override
    public void printLeft(StringWriter writer) {
        writer.write("fp ");

        if (number != null) {
            writer.write(number);
        }
    }
}