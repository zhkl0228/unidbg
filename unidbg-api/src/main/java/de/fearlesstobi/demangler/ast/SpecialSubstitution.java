package de.fearlesstobi.demangler.ast;

import java.io.StringWriter;

public class SpecialSubstitution extends BaseNode {
    public enum SpecialType {
        Allocator,
        BasicString,
        String,
        IStream,
        OStream,
        IOStream
    }

    private final SpecialType specialSubstitutionKey;

    public SpecialSubstitution(SpecialType specialSubstitutionKey) {
        super(NodeType.SpecialSubstitution);
        this.specialSubstitutionKey = specialSubstitutionKey;
    }

    public void SetExtended() {
        type = NodeType.ExpandedSpecialSubstitution;
    }

    @Override
    String getName() {
        switch (specialSubstitutionKey) {
            case Allocator:
                return "allocator";
            case BasicString:
                return "basic_string";
            case String:
                if (type == NodeType.ExpandedSpecialSubstitution) {
                    return "basic_string";
                }

                return "string";
            case IStream:
                return "istream";
            case OStream:
                return "ostream";
            case IOStream:
                return "iostream";
        }

        return null;
    }

    //No override
    private String GetExtendedName() {
        switch (specialSubstitutionKey) {
            case Allocator:
                return "std::allocator";
            case BasicString:
                return "std::basic_string";
            case String:
                return "std::basic_string<char, std::char_traits<char>, std::allocator<char> >";
            case IStream:
                return "std::basic_istream<char, std::char_traits<char> >";
            case OStream:
                return "std::basic_ostream<char, std::char_traits<char> >";
            case IOStream:
                return "std::basic_iostream<char, std::char_traits<char> >";
        }

        return "";
    }

    @Override
    public void printLeft(StringWriter writer) {
        if (type == NodeType.ExpandedSpecialSubstitution) {
            writer.write(GetExtendedName());
        } else {
            writer.write("std::");
            writer.write(getName());
        }
    }
}