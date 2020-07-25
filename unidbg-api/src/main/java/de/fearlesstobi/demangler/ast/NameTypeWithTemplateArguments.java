package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class NameTypeWithTemplateArguments extends BaseNode {
    private final BaseNode prev;
    private final BaseNode templateArgument;

    public NameTypeWithTemplateArguments(BaseNode prev, BaseNode templateArgument) {
        super(NodeType.NameTypeWithTemplateArguments);
        this.prev = prev;
        this.templateArgument = templateArgument;
    }

    @Override
    public String getName() {
        return prev.getName();
    }

    @Override
    public void printLeft(StringWriter writer) {
        prev.print(writer);
        templateArgument.print(writer);
    }
}