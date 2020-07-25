package de.fearlesstobi.demangler;

import de.fearlesstobi.demangler.ast.*;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class Demangler {
    private static final String base36 = "0123456789abcdefghijklmnopqrstuvwxyz";
    private final List<BaseNode> substitutionList = new LinkedList<>();
    private List<BaseNode> templateParamList = new LinkedList<>();

    private final String mangled;

    private int position;
    private final int length;

    private boolean canForwardTemplateReference;
    private boolean canParseTemplateArgs;

    private Demangler(String mangled) {
        this.mangled = mangled;
        position = 0;
        length = mangled.length();
        canParseTemplateArgs = true;
    }

    private boolean consumeIf(String toConsume) {
        String mangledPart = mangled.substring(position);

        if (mangledPart.startsWith(toConsume)) {
            position += toConsume.length();

            return true;
        }

        return false;
    }

    private String peekString(int offset, int length) {
        if (position + offset >= length) {
            return null;
        }

        return mangled.substring(position + offset, position + offset + length);
    }

    private char peek() {
        return peek(0);
    }

    private char peek(int offset) {
        if (position + offset >= length) {
            return '\0';
        }

        return mangled.charAt(position + offset);
    }

    private char consume() {
        if (position < length) {
            return mangled.charAt(position++);
        }

        return '\0';
    }

    private int count() {
        return length - position;
    }

    private static int fromBase36(String encoded) {
        char[] encodedArray = encoded.toLowerCase().toCharArray();
        char[] reversedEncoded = new char[encodedArray.length];
        //TODO: Check
        for (int i = 0; i < encodedArray.length; i++) {
            reversedEncoded[encodedArray.length - i - 1] = encodedArray[i];
        }

        int result = 0;

        for (int i = 0; i < reversedEncoded.length; i++) {
            int value = base36.indexOf(reversedEncoded[i]);
            if (value == -1) {
                return -1;
            }

            result += value * (int) Math.pow(36, i);
        }

        return result;
    }

    private int parseSeqId() {
        String part = mangled.substring(position);
        int seqIdLen = 0;

        for (; seqIdLen < part.length(); seqIdLen++) {
            if (!Character.isLetterOrDigit(part.charAt(seqIdLen))) {
                break;
            }
        }

        position += seqIdLen;

        return fromBase36(part.substring(0, seqIdLen));
    }

    //   <substitution> ::= S <seq-id> _
    //                  ::= S_
    //                  ::= St # std::
    //                  ::= Sa # std::allocator
    //                  ::= Sb # std::basic_String
    //                  ::= Ss # std::basic_String<char, std::char_traits<char>, std::allocator<char> >
    //                  ::= Si # std::basic_istream<char, std::char_traits<char> >
    //                  ::= So # std::basic_ostream<char, std::char_traits<char> >
    //                  ::= Sd # std::basic_iostream<char, std::char_traits<char> >
    private BaseNode parseSubstitution() {
        if (!consumeIf("S")) {
            return null;
        }

        char substitutionSecondChar = peek();
        if (Character.isLowerCase(substitutionSecondChar)) {
            switch (substitutionSecondChar) {
                case 'a':
                    position++;
                    return new SpecialSubstitution(SpecialSubstitution.SpecialType.Allocator);
                case 'b':
                    position++;
                    return new SpecialSubstitution(SpecialSubstitution.SpecialType.BasicString);
                case 's':
                    position++;
                    return new SpecialSubstitution(SpecialSubstitution.SpecialType.String);
                case 'i':
                    position++;
                    return new SpecialSubstitution(SpecialSubstitution.SpecialType.IStream);
                case 'o':
                    position++;
                    return new SpecialSubstitution(SpecialSubstitution.SpecialType.OStream);
                case 'd':
                    position++;
                    return new SpecialSubstitution(SpecialSubstitution.SpecialType.IOStream);
                default:
                    return null;
            }
        }

        // ::= S_
        if (consumeIf("_")) {
            if (!substitutionList.isEmpty()) {
                return substitutionList.get(0);
            }

            return null;
        }

        //                ::= S <seq-id> _
        int seqId = parseSeqId();
        if (seqId < 0) {
            return null;
        }

        seqId++;

        if (!consumeIf("_") || seqId >= substitutionList.size()) {
            return null;
        }

        return substitutionList.get(seqId);
    }

    // NOTE: thoses data aren't used in the output
    //  <call-offset> ::= h <nv-offset> _
    //                ::= v <v-offset> _
    //  <nv-offset>   ::= <offset number>
    //                    # non-virtual base override
    //  <v-offset>    ::= <offset number> _ <virtual offset number>
    //                    # virtual base override, with vcall offset
    private boolean parseCallOffset() {
        if (consumeIf("h")) {
            return parseNumber(true).length() == 0 || !consumeIf("_");
        } else if (consumeIf("v")) {
            return parseNumber(true).length() == 0 || !consumeIf("_") || parseNumber(true).length() == 0 || !consumeIf("_");
        }

        return true;
    }


    //   <class-enum-type> ::= <name>     # non-dependent type name, dependent type name, or dependent typename-specifier
    //                     ::= Ts <name>  # dependent elaborated type specifier using 'struct' or 'class'
    //                     ::= Tu <name>  # dependent elaborated type specifier using 'union'
    //                     ::= Te <name>  # dependent elaborated type specifier using 'enum'
    private BaseNode parseClassEnumType() {
        String elaboratedType = null;

        if (consumeIf("Ts")) {
            elaboratedType = "struct";
        } else if (consumeIf("Tu")) {
            elaboratedType = "union";
        } else if (consumeIf("Te")) {
            elaboratedType = "enum";
        }

        BaseNode name = parseName();
        if (name == null) {
            return null;
        }

        if (elaboratedType == null) {
            return name;
        }

        return new ElaboratedType(elaboratedType, name);
    }

    //  <function-type>         ::= [<CV-qualifiers>] [<exception-spec>] [Dx] F [Y] <bare-function-type> [<ref-qualifier>] E
    //  <bare-function-type>    ::= <signature type>+
    //                              # types are possible return type, then parameter types
    //  <exception-spec>        ::= Do                # non-throwing exception-specification (e.g., noexcept, throw())
    //                          ::= DO <expression> E # computed (instantiation-dependent) noexcept
    //                          ::= Dw <type>+ E      # dynamic exception specification with instantiation-dependent types
    private BaseNode parseFunctionType() {
        int cvQualifiers = parseCvQualifiers();

        BaseNode exceptionSpec = null;

        if (consumeIf("Do")) {
            exceptionSpec = new NameType("noexcept");
        } else if (consumeIf("DO")) {
            BaseNode expression = parseExpression();
            if (expression == null || !consumeIf("E")) {
                return null;
            }

            exceptionSpec = new NoexceptSpec(expression);
        } else if (consumeIf("Dw")) {
            List<BaseNode> types = new ArrayList<>();

            while (!consumeIf("E")) {
                BaseNode type = parseType();
                if (type == null) {
                    return null;
                }

                types.add(type);
            }

            exceptionSpec = new DynamicExceptionSpec(new NodeArray(types));
        }

        // We don't need the transaction
        consumeIf("Dx");

        if (!consumeIf("F")) {
            return null;
        }

        // extern "C"
        consumeIf("Y");

        BaseNode returnType = parseType();
        if (returnType == null) {
            return null;
        }

        int referenceQualifier = Reference.None;
        List<BaseNode> params = new ArrayList<>();

        while (true) {
            if (consumeIf("E")) {
                break;
            }

            if (consumeIf("v")) {
                continue;
            }

            if (consumeIf("RE")) {
                referenceQualifier = Reference.LValue;
                break;
            } else if (consumeIf("OE")) {
                referenceQualifier = Reference.RValue;
                break;
            }

            BaseNode type = parseType();
            if (type == null) {
                return null;
            }

            params.add(type);
        }

        return new FunctionType(returnType, new NodeArray(params), new CvType(cvQualifiers, null), new SimpleReferenceType(referenceQualifier, null), exceptionSpec);
    }

    //   <array-type> ::= A <positive dimension number> _ <element type>
    //                ::= A [<dimension expression>] _ <element type>
    private BaseNode parseArrayType() {
        if (!consumeIf("A")) {
            return null;
        }

        BaseNode elementType;
        if (Character.isDigit(peek())) {
            String dimension = parseNumber();
            if (dimension.length() == 0 || !consumeIf("_")) {
                return null;
            }

            elementType = parseType();
            if (elementType == null) {
                return null;
            }

            return new ArrayType(elementType, dimension);
        }

        if (!consumeIf("_")) {
            BaseNode dimensionExpression = parseExpression();
            if (dimensionExpression == null || !consumeIf("_")) {
                return null;
            }

            elementType = parseType();
            if (elementType == null) {
                return null;
            }

            return new ArrayType(elementType, dimensionExpression);
        }

        elementType = parseType();
        if (elementType == null) {
            return null;
        }

        return new ArrayType(elementType);
    }

    private BaseNode parseType() {
        return parseType(null);
    }

    // <type>  ::= <builtin-type>
    //         ::= <qualified-type> (PARTIAL)
    //         ::= <function-type>
    //         ::= <class-enum-type>
    //         ::= <array-type> (TODO)
    //         ::= <pointer-to-member-type> (TODO)
    //         ::= <template-param>
    //         ::= <template-template-param> <template-args>
    //         ::= <decltype>
    //         ::= P <type>        # pointer
    //         ::= R <type>        # l-value reference
    //         ::= O <type>        # r-value reference (C++11)
    //         ::= C <type>        # complex pair (C99)
    //         ::= G <type>        # imaginary (C99)
    //         ::= <substitution>  # See Compression below
    private BaseNode parseType(NameparserContext context) {
        // Temporary context
        if (context == null) {
            context = new NameparserContext();
        }

        BaseNode result;
        switch (peek()) {
            case 'r':
            case 'V':
            case 'K':
                int typePos = 0;

                if (peek(typePos) == 'r') {
                    typePos++;
                }

                if (peek(typePos) == 'V') {
                    typePos++;
                }

                if (peek(typePos) == 'K') {
                    typePos++;
                }

                if (peek(typePos) == 'F' || (peek(typePos) == 'D' && (peek(typePos + 1) == 'o' || peek(typePos + 1) == 'O' || peek(typePos + 1) == 'w' || peek(typePos + 1) == 'x'))) {
                    result = parseFunctionType();
                    break;
                }

                int cv = parseCvQualifiers();

                result = parseType(context);

                if (result == null) {
                    return null;
                }

                result = new CvType(cv, result);
                break;
            case 'U':
                // TODO: <extended-qualifier>
                return null;
            case 'v':
                position++;
                return new NameType("void");
            case 'w':
                position++;
                return new NameType("wchar_t");
            case 'b':
                position++;
                return new NameType("boolean");
            case 'c':
                position++;
                return new NameType("char");
            case 'a':
                position++;
                return new NameType("signed char");
            case 'h':
                position++;
                return new NameType("unsigned char");
            case 's':
                position++;
                return new NameType("short");
            case 't':
                position++;
                return new NameType("unsigned short");
            case 'i':
                position++;
                return new NameType("int");
            case 'j':
                position++;
                return new NameType("unsigned int");
            case 'l':
                position++;
                return new NameType("long");
            case 'm':
                position++;
                return new NameType("unsigned long");
            case 'x':
                position++;
                return new NameType("long long");
            case 'y':
                position++;
                return new NameType("unsigned long long");
            case 'n':
                position++;
                return new NameType("__int128");
            case 'o':
                position++;
                return new NameType("unsigned __int128");
            case 'f':
                position++;
                return new NameType("float");
            case 'd':
                position++;
                return new NameType("double");
            case 'e':
                position++;
                return new NameType("long double");
            case 'g':
                position++;
                return new NameType("__float128");
            case 'z':
                position++;
                return new NameType("...");
            case 'u':
                position++;
                return parseSourceName();
            case 'D':
                switch (peek(1)) {
                    case 'd':
                        position += 2;
                        return new NameType("decimal64");
                    case 'e':
                        position += 2;
                        return new NameType("decimal128");
                    case 'f':
                        position += 2;
                        return new NameType("decimal32");
                    case 'h':
                        position += 2;
                        // FIXME: GNU c++flit returns this but that is not what is supposed to be returned.
                        return new NameType("half");
                    // return new de.fearlesstobi.demangler.ast.NameType("decimal16");
                    case 'i':
                        position += 2;
                        return new NameType("char32_t");
                    case 's':
                        position += 2;
                        return new NameType("char16_t");
                    case 'a':
                        position += 2;
                        return new NameType("decltype(auto)");
                    case 'n':
                        position += 2;
                        // FIXME: GNU c++flit returns this but that is not what is supposed to be returned.
                        return new NameType("decltype(nullptr)");
                    // return new de.fearlesstobi.demangler.ast.NameType("std::nullptr_t");
                    case 't':
                    case 'T':
                        position += 2;
                        result = parseDecltype();
                        break;
                    case 'o':
                    case 'O':
                    case 'w':
                    case 'x':
                        result = parseFunctionType();
                        break;
                    default:
                        return null;
                }
                break;
            case 'F':
                result = parseFunctionType();
                break;
            case 'A':
                return parseArrayType();
            case 'M':
                // TODO: <pointer-to-member-type>
                position++;
                return null;
            case 'T':
                // might just be a class enum type
                if (peek(1) == 's' || peek(1) == 'u' || peek(1) == 'e') {
                    result = parseClassEnumType();
                    break;
                }

                result = parseTemplateParam();
                if (result == null) {
                    return null;
                }

                if (canParseTemplateArgs && peek() == 'I') {
                    BaseNode templateArguments = parseTemplateArguments();
                    if (templateArguments == null) {
                        return null;
                    }

                    result = new NameTypeWithTemplateArguments(result, templateArguments);
                }
                break;
            case 'P':
                position++;
                result = parseType(context);

                if (result == null) {
                    return null;
                }

                result = new PointerType(result);
                break;
            case 'R':
                position++;
                result = parseType(context);

                if (result == null) {
                    return null;
                }

                result = new ReferenceType("&", result);
                break;
            case 'O':
                position++;
                result = parseType(context);

                if (result == null) {
                    return null;
                }

                result = new ReferenceType("&&", result);
                break;
            case 'C':
                position++;
                result = parseType(context);

                if (result == null) {
                    return null;
                }

                result = new PostfixQualifiedType(" complex", result);
                break;
            case 'G':
                position++;
                result = parseType(context);

                if (result == null) {
                    return null;
                }

                result = new PostfixQualifiedType(" imaginary", result);
                break;
            case 'S':
                if (peek(1) != 't') {
                    BaseNode substitution = parseSubstitution();
                    if (substitution == null) {
                        return null;
                    }

                    if (canParseTemplateArgs && peek() == 'I') {
                        BaseNode templateArgument = parseTemplateArgument();
                        if (templateArgument == null) {
                            return null;
                        }

                        result = new NameTypeWithTemplateArguments(substitution, templateArgument);
                        break;
                    }
                    return substitution;
                } else {
                    result = parseClassEnumType();
                    break;
                }
            default:
                result = parseClassEnumType();
                break;
        }
        if (result != null) {
            substitutionList.add(result);
        }

        return result;
    }

    // <special-name> ::= TV <type> # virtual table
    //                ::= TT <type> # VTT structure (construction vtable index)
    //                ::= TI <type> # typeinfo structure
    //                ::= TS <type> # typeinfo name (null-terminated byte String)
    //                ::= Tc <call-offset> <call-offset> <base encoding>
    //                ::= TW <object name> # Thread-local wrapper
    //                ::= TH <object name> # Thread-local initialization
    //                ::= T <call-offset> <base encoding>
    //                              # base is the nominal target function of thunk
    //                ::= GV <object name>	# Guard variable for one-time initialization
    private BaseNode parseSpecialName(NameparserContext context) {
        if (peek() != 'T') {
            if (consumeIf("GV")) {
                BaseNode name = parseName();
                if (name == null) {
                    return null;
                }

                return new SpecialName("guard variable for ", name);
            }
            return null;
        }

        BaseNode node;
        switch (peek(1)) {
            // ::= TV <type>    # virtual table
            case 'V':
                position += 2;
                node = parseType(context);
                if (node == null) {
                    return null;
                }

                return new SpecialName("vtable for ", node);
            // ::= TT <type>    # VTT structure (construction vtable index)
            case 'T':
                position += 2;
                node = parseType(context);
                if (node == null) {
                    return null;
                }

                return new SpecialName("VTT for ", node);
            // ::= TI <type>    # typeinfo structure
            case 'I':
                position += 2;
                node = parseType(context);
                if (node == null) {
                    return null;
                }

                return new SpecialName("typeinfo for ", node);
            // ::= TS <type> # typeinfo name (null-terminated byte String)
            case 'S':
                position += 2;
                node = parseType(context);
                if (node == null) {
                    return null;
                }

                return new SpecialName("typeinfo name for ", node);
            // ::= Tc <call-offset> <call-offset> <base encoding>
            case 'c':
                position += 2;
                if (parseCallOffset() || parseCallOffset()) {
                    return null;
                }

                node = parseEncoding();
                if (node == null) {
                    return null;
                }

                return new SpecialName("covariant return thunk to ", node);
            // extension ::= TC <first type> <number> _ <second type>
            case 'C':
                position += 2;
                BaseNode firstType = parseType();
                if (firstType == null || parseNumber(true).length() == 0 || !consumeIf("_")) {
                    return null;
                }

                BaseNode secondType = parseType();

                return new CtorVtableSpecialName(secondType, firstType);
            // ::= TH <object name> # Thread-local initialization
            case 'H':
                position += 2;
                node = parseName();
                if (node == null) {
                    return null;
                }

                return new SpecialName("thread-local initialization routine for ", node);
            // ::= TW <object name> # Thread-local wrapper
            case 'W':
                position += 2;
                node = parseName();
                if (node == null) {
                    return null;
                }

                return new SpecialName("thread-local wrapper routine for ", node);
            default:
                position++;
                boolean isVirtual = peek() == 'v';
                if (parseCallOffset()) {
                    return null;
                }

                node = parseEncoding();
                if (node == null) {
                    return null;
                }

                if (isVirtual) {
                    return new SpecialName("virtual thunk to ", node);
                }

                return new SpecialName("non-virtual thunk to ", node);
        }
    }

    // <CV-qualifiers>      ::= [r] [V] [K] # restrict (C99), volatile, const
    private int parseCvQualifiers() {
        int qualifiers = CvType.Cv.None;

        if (consumeIf("r")) {
            qualifiers |= CvType.Cv.Restricted;
        }
        if (consumeIf("V")) {
            qualifiers |= CvType.Cv.Volatile;
        }
        if (consumeIf("K")) {
            qualifiers |= CvType.Cv.Const;
        }

        return qualifiers;
    }


    // <ref-qualifier>      ::= R              # & ref-qualifier
    // <ref-qualifier>      ::= O              # && ref-qualifier
    private SimpleReferenceType parseRefQualifiers() {
        int result = Reference.None;
        if (consumeIf("O")) {
            result = Reference.RValue;
        } else if (consumeIf("R")) {
            result = Reference.LValue;
        }
        return new SimpleReferenceType(result, null);
    }

    private BaseNode createNameNode(BaseNode prev, BaseNode name, NameparserContext context) {
        BaseNode result = name;
        if (prev != null) {
            result = new NestedName(name, prev);
        }

        if (context != null) {
            context.finishWithTemplateArguments = false;
        }

        return result;
    }

    private int parsePositiveNumber() {
        String part = mangled.substring(position);
        int numberLength = 0;

        for (; numberLength < part.length(); numberLength++) {
            if (!Character.isDigit(part.charAt(numberLength))) {
                break;
            }
        }

        position += numberLength;

        if (numberLength == 0) {
            return -1;
        }

        return Integer.parseInt(part.substring(0, numberLength));
    }


    private String parseNumber() {
        return parseNumber(false);
    }

    private String parseNumber(boolean isSigned) {
        if (isSigned) {
            consumeIf("n");
        }

        if (count() == 0 || !Character.isDigit(mangled.charAt(position))) {
            return null;
        }

        String part = mangled.substring(position);
        int numberLength = 0;

        for (; numberLength < part.length(); numberLength++) {
            if (!Character.isDigit(part.charAt(numberLength))) {
                break;
            }
        }

        position += numberLength;

        return part.substring(0, numberLength);
    }

    // <source-name> ::= <positive length number> <identifier>
    private BaseNode parseSourceName() {
        int length = parsePositiveNumber();
        if (count() < length || length <= 0) {
            return null;
        }

        String name = mangled.substring(position, position + length);
        position += length;
        if (name.startsWith("_GLOBAL__N")) {
            return new NameType("(anonymous namespace)");
        }

        return new NameType(name);
    }

    // <operator-name> ::= nw    # new
    //                 ::= na    # new[]
    //                 ::= dl    # delete
    //                 ::= da    # delete[]
    //                 ::= ps    # + (unary)
    //                 ::= ng    # - (unary)
    //                 ::= ad    # & (unary)
    //                 ::= de    # * (unary)
    //                 ::= co    # ~
    //                 ::= pl    # +
    //                 ::= mi    # -
    //                 ::= ml    # *
    //                 ::= dv    # /
    //                 ::= rm    # %
    //                 ::= an    # &
    //                 ::= or    # |
    //                 ::= eo    # ^
    //                 ::= aS    # =
    //                 ::= pL    # +=
    //                 ::= mI    # -=
    //                 ::= mL    # *=
    //                 ::= dV    # /=
    //                 ::= rM    # %=
    //                 ::= aN    # &=
    //                 ::= oR    # |=
    //                 ::= eO    # ^=
    //                 ::= ls    # <<
    //                 ::= rs    # >>
    //                 ::= lS    # <<=
    //                 ::= rS    # >>=
    //                 ::= eq    # ==
    //                 ::= ne    # !=
    //                 ::= lt    # <
    //                 ::= gt    # >
    //                 ::= le    # <=
    //                 ::= ge    # >=
    //                 ::= ss    # <=>
    //                 ::= nt    # !
    //                 ::= aa    # &&
    //                 ::= oo    # ||
    //                 ::= pp    # ++ (postfix in <expression> context)
    //                 ::= mm    # -- (postfix in <expression> context)
    //                 ::= cm    # ,
    //                 ::= pm    # ->*
    //                 ::= pt    # ->
    //                 ::= cl    # ()
    //                 ::= ix    # []
    //                 ::= qu    # ?
    //                 ::= cv <type>    # (cast) (TODO)
    //                 ::= li <source-name>          # operator ""
    //                 ::= v <digit> <source-name>    # vendor extended operator (TODO)
    private BaseNode parseOperatorName(NameparserContext context) {
        switch (peek()) {
            case 'a':
                switch (peek(1)) {
                    case 'a':
                        position += 2;
                        return new NameType("operator&&");
                    case 'd':
                    case 'n':
                        position += 2;
                        return new NameType("operator&");
                    case 'N':
                        position += 2;
                        return new NameType("operator&=");
                    case 'S':
                        position += 2;
                        return new NameType("operator=");
                    default:
                        return null;
                }
            case 'c':
                switch (peek(1)) {
                    case 'l':
                        position += 2;
                        return new NameType("operator()");
                    case 'm':
                        position += 2;
                        return new NameType("operator,");
                    case 'o':
                        position += 2;
                        return new NameType("operator~");
                    case 'v':
                        position += 2;

                        boolean canparseTemplateArgsBackup = canParseTemplateArgs;
                        boolean canForwardTemplateReferenceBackup = canForwardTemplateReference;

                        canParseTemplateArgs = false;
                        canForwardTemplateReference = canForwardTemplateReferenceBackup || context != null;

                        BaseNode type = parseType();

                        canParseTemplateArgs = canparseTemplateArgsBackup;
                        canForwardTemplateReference = canForwardTemplateReferenceBackup;

                        if (type == null) {
                            return null;
                        }

                        if (context != null) {
                            context.ctorDtorConversion = true;
                        }

                        return new ConversionOperatorType(type);
                    default:
                        return null;
                }
            case 'd':
                switch (peek(1)) {
                    case 'a':
                        position += 2;
                        return new NameType("operator delete[]");
                    case 'e':
                        position += 2;
                        return new NameType("operator*");
                    case 'l':
                        position += 2;
                        return new NameType("operator delete");
                    case 'v':
                        position += 2;
                        return new NameType("operator/");
                    case 'V':
                        position += 2;
                        return new NameType("operator/=");
                    default:
                        return null;
                }
            case 'e':
                switch (peek(1)) {
                    case 'o':
                        position += 2;
                        return new NameType("operator^");
                    case 'O':
                        position += 2;
                        return new NameType("operator^=");
                    case 'q':
                        position += 2;
                        return new NameType("operator==");
                    default:
                        return null;
                }
            case 'g':
                switch (peek(1)) {
                    case 'e':
                        position += 2;
                        return new NameType("operator>=");
                    case 't':
                        position += 2;
                        return new NameType("operator>");
                    default:
                        return null;
                }
            case 'i':
                if (peek(1) == 'x') {
                    position += 2;
                    return new NameType("operator[]");
                }
                return null;
            case 'l':
                switch (peek(1)) {
                    case 'e':
                        position += 2;
                        return new NameType("operator<=");
                    case 'i':
                        position += 2;
                        BaseNode sourceName = parseSourceName();
                        if (sourceName == null) {
                            return null;
                        }

                        return new LiteralOperator(sourceName);
                    case 's':
                        position += 2;
                        return new NameType("operator<<");
                    case 'S':
                        position += 2;
                        return new NameType("operator<<=");
                    case 't':
                        position += 2;
                        return new NameType("operator<");
                    default:
                        return null;
                }
            case 'm':
                switch (peek(1)) {
                    case 'i':
                        position += 2;
                        return new NameType("operator-");
                    case 'I':
                        position += 2;
                        return new NameType("operator-=");
                    case 'l':
                        position += 2;
                        return new NameType("operator*");
                    case 'L':
                        position += 2;
                        return new NameType("operator*=");
                    case 'm':
                        position += 2;
                        return new NameType("operator--");
                    default:
                        return null;
                }
            case 'n':
                switch (peek(1)) {
                    case 'a':
                        position += 2;
                        return new NameType("operator new[]");
                    case 'e':
                        position += 2;
                        return new NameType("operator!=");
                    case 'g':
                        position += 2;
                        return new NameType("operator-");
                    case 't':
                        position += 2;
                        return new NameType("operator!");
                    case 'w':
                        position += 2;
                        return new NameType("operator new");
                    default:
                        return null;
                }
            case 'o':
                switch (peek(1)) {
                    case 'o':
                        position += 2;
                        return new NameType("operator||");
                    case 'r':
                        position += 2;
                        return new NameType("operator|");
                    case 'R':
                        position += 2;
                        return new NameType("operator|=");
                    default:
                        return null;
                }
            case 'p':
                switch (peek(1)) {
                    case 'm':
                        position += 2;
                        return new NameType("operator->*");
                    case 's':
                    case 'l':
                        position += 2;
                        return new NameType("operator+");
                    case 'L':
                        position += 2;
                        return new NameType("operator+=");
                    case 'p':
                        position += 2;
                        return new NameType("operator++");
                    case 't':
                        position += 2;
                        return new NameType("operator->");
                    default:
                        return null;
                }
            case 'q':
                if (peek(1) == 'u') {
                    position += 2;
                    return new NameType("operator?");
                }
                return null;
            case 'r':
                switch (peek(1)) {
                    case 'm':
                        position += 2;
                        return new NameType("operator%");
                    case 'M':
                        position += 2;
                        return new NameType("operator%=");
                    case 's':
                        position += 2;
                        return new NameType("operator>>");
                    case 'S':
                        position += 2;
                        return new NameType("operator>>=");
                    default:
                        return null;
                }
            case 's':
                if (peek(1) == 's') {
                    position += 2;
                    return new NameType("operator<=>");
                }
                return null;
            case 'v':
                // TODO: ::= v <digit> <source-name>    # vendor extended operator
                return null;
            default:
                return null;
        }
    }

    // <unqualified-name> ::= <operator-name> [<abi-tags> (TODO)]
    //                    ::= <ctor-dtor-name> (TODO)
    //                    ::= <source-name>
    //                    ::= <unnamed-type-name> (TODO)
    //                    ::= DC <source-name>+ E      # structured binding declaration (TODO)
    private BaseNode parseUnqualifiedName(NameparserContext context) {
        BaseNode result = null;
        char c = peek();
        if (c == 'U') {
            // TODO: Unnamed type Name
            // throw new Exception("Unnamed type Name not implemented");
        } else if (Character.isDigit(c)) {
            result = parseSourceName();
        } else if (consumeIf("DC")) {
            // TODO: Structured Binding Declaration
            // throw new Exception("Structured Binding Declaration not implemented");
        } else {
            result = parseOperatorName(context);
        }

        if (result != null) {
            // TODO: ABI Tags
            // throw new Exception("ABI Tags not implemented");
        }
        return result;
    }

    // <ctor-dtor-name> ::= C1  # complete object constructor
    //                  ::= C2  # base object constructor
    //                  ::= C3  # complete object allocating constructor
    //                  ::= D0  # deleting destructor
    //                  ::= D1  # complete object destructor
    //                  ::= D2  # base object destructor 
    private BaseNode parseCtorDtorName(NameparserContext context, BaseNode prev) {
        if (prev.type == NodeType.SpecialSubstitution && prev instanceof SpecialSubstitution) {
            ((SpecialSubstitution) prev).SetExtended();
        }

        if (consumeIf("C")) {
            boolean isInherited = consumeIf("I");

            char ctorDtorType = peek();
            if (ctorDtorType != '1' && ctorDtorType != '2' && ctorDtorType != '3') {
                return null;
            }

            position++;

            if (context != null) {
                context.ctorDtorConversion = true;
            }

            if (isInherited && parseName(context) == null) {
                return null;
            }

            return new CtorDtorNameType(prev, false);
        }

        if (consumeIf("D")) {
            char c = peek();
            if (c != '0' && c != '1' && c != '2') {
                return null;
            }

            position++;

            if (context != null) {
                context.ctorDtorConversion = true;
            }

            return new CtorDtorNameType(prev, true);
        }

        return null;
    }

    // <function-param> ::= fp <top-level CV-qualifiers> _                                                                                           # L == 0, first parameter
    //                  ::= fp <top-level CV-qualifiers> <parameter-2 non-negative number> _                                                         # L == 0, second and later parameters
    //                  ::= fL <L-1 non-negative number> p <top-level CV-qualifiers> _                                                               # L > 0, first parameter
    //                  ::= fL <L-1 non-negative number> p <top-level CV-qualifiers> <parameter-2 non-negative number> _                             # L > 0, second and later parameters
    private BaseNode parseFunctionParameter() {
        if (consumeIf("fp")) {
            // ignored
            parseCvQualifiers();

            if (!consumeIf("_")) {
                return null;
            }

            return new FunctionParameter(parseNumber());
        } else if (consumeIf("fL")) {
            String l1Number = parseNumber();
            if (l1Number == null || l1Number.length() == 0) {
                return null;
            }

            if (!consumeIf("p")) {
                return null;
            }

            // ignored
            parseCvQualifiers();

            if (!consumeIf("_")) {
                return null;
            }

            return new FunctionParameter(parseNumber());
        }

        return null;
    }

    // <fold-expr> ::= fL <binary-operator-name> <expression> <expression>
    //             ::= fR <binary-operator-name> <expression> <expression>
    //             ::= fl <binary-operator-name> <expression>
    //             ::= fr <binary-operator-name> <expression>
    private BaseNode parseFoldExpression() {
        if (!consumeIf("f")) {
            return null;
        }

        char foldKind = peek();
        boolean hasInitializer = foldKind == 'L' || foldKind == 'R';
        boolean isLeftFold = foldKind == 'l' || foldKind == 'L';

        if (!isLeftFold && !(foldKind == 'r' || foldKind == 'R')) {
            return null;
        }

        position++;

        String operatorName;

        switch (peekString(0, 2)) {
            case "aa":
                operatorName = "&&";
                break;
            case "an":
                operatorName = "&";
                break;
            case "aN":
                operatorName = "&=";
                break;
            case "aS":
                operatorName = "=";
                break;
            case "cm":
                operatorName = ",";
                break;
            case "ds":
                operatorName = ".*";
                break;
            case "dv":
                operatorName = "/";
                break;
            case "dV":
                operatorName = "/=";
                break;
            case "eo":
                operatorName = "^";
                break;
            case "eO":
                operatorName = "^=";
                break;
            case "eq":
                operatorName = "==";
                break;
            case "ge":
                operatorName = ">=";
                break;
            case "gt":
                operatorName = ">";
                break;
            case "le":
                operatorName = "<=";
                break;
            case "ls":
                operatorName = "<<";
                break;
            case "lS":
                operatorName = "<<=";
                break;
            case "lt":
                operatorName = "<";
                break;
            case "mi":
                operatorName = "-";
                break;
            case "mI":
                operatorName = "-=";
                break;
            case "ml":
                operatorName = "*";
                break;
            case "mL":
                operatorName = "*=";
                break;
            case "ne":
                operatorName = "!=";
                break;
            case "oo":
                operatorName = "||";
                break;
            case "or":
                operatorName = "|";
                break;
            case "oR":
                operatorName = "|=";
                break;
            case "pl":
                operatorName = "+";
                break;
            case "pL":
                operatorName = "+=";
                break;
            case "rm":
                operatorName = "%";
                break;
            case "rM":
                operatorName = "%=";
                break;
            case "rs":
                operatorName = ">>";
                break;
            case "rS":
                operatorName = ">>=";
                break;
            default:
                return null;
        }

        position += 2;

        BaseNode expression = parseExpression();
        if (expression == null) {
            return null;
        }

        BaseNode initializer = null;

        if (hasInitializer) {
            initializer = parseExpression();
            if (initializer == null) {
                return null;
            }
        }

        if (isLeftFold && initializer != null) {
            BaseNode temp = expression;
            expression = initializer;
            initializer = temp;
        }

        return new FoldExpression(isLeftFold, operatorName, new PackedTemplateParameterExpansion(expression), initializer);
    }


    //                ::= cv <type> <expression>                               # type (expression), conversion with one argument
    //                ::= cv <type> _ <expression>* E                          # type (expr-list), conversion with other than one argument
    private BaseNode parseConversionExpression() {
        if (!consumeIf("cv")) {
            return null;
        }

        boolean canparseTemplateArgsBackup = canParseTemplateArgs;
        canParseTemplateArgs = false;
        BaseNode type = parseType();
        canParseTemplateArgs = canparseTemplateArgsBackup;

        if (type == null) {
            return null;
        }

        List<BaseNode> expressions = new ArrayList<>();
        if (consumeIf("_")) {
            while (!consumeIf("E")) {
                BaseNode expression = parseExpression();
                if (expression == null) {
                    return null;
                }

                expressions.add(expression);
            }
        } else {
            BaseNode expression = parseExpression();
            if (expression == null) {
                return null;
            }

            expressions.add(expression);
        }

        return new ConversionExpression(type, new NodeArray(expressions));
    }

    private BaseNode parseBinaryExpression(String name) {
        BaseNode leftPart = parseExpression();
        if (leftPart == null) {
            return null;
        }

        BaseNode rightPart = parseExpression();
        if (rightPart == null) {
            return null;
        }

        return new BinaryExpression(leftPart, name, rightPart);
    }

    private BaseNode parsePrefixExpression(String name) {
        BaseNode expression = parseExpression();
        if (expression == null) {
            return null;
        }

        return new PrefixExpression(name, expression);
    }


    // <braced-expression> ::= <expression>
    //                     ::= di <field source-name> <braced-expression>    # .name = expr
    //                     ::= dx <index expression> <braced-expression>     # [expr] = expr
    //                     ::= dX <range begin expression> <range end expression> <braced-expression>
    //                                                                       # [expr ... expr] = expr
    private BaseNode parseBracedExpression() {
        if (peek() == 'd') {
            BaseNode bracedExpressionNode;
            switch (peek(1)) {
                case 'i':
                    position += 2;
                    BaseNode field = parseSourceName();
                    if (field == null) {
                        return null;
                    }

                    bracedExpressionNode = parseBracedExpression();
                    if (bracedExpressionNode == null) {
                        return null;
                    }

                    return new BracedExpression(field, bracedExpressionNode, false);
                case 'x':
                    position += 2;
                    BaseNode index = parseExpression();
                    if (index == null) {
                        return null;
                    }

                    bracedExpressionNode = parseBracedExpression();
                    if (bracedExpressionNode == null) {
                        return null;
                    }

                    return new BracedExpression(index, bracedExpressionNode, true);
                case 'X':
                    position += 2;
                    BaseNode rangeBeginExpression = parseExpression();
                    if (rangeBeginExpression == null) {
                        return null;
                    }

                    BaseNode rangeEndExpression = parseExpression();
                    if (rangeEndExpression == null) {
                        return null;
                    }

                    bracedExpressionNode = parseBracedExpression();
                    if (bracedExpressionNode == null) {
                        return null;
                    }

                    return new BracedRangeExpression(rangeBeginExpression, rangeEndExpression, bracedExpressionNode);
            }
        }

        return parseExpression();
    }

    //               ::= [gs] nw <expression>* _ <type> E                    # new (expr-list) type
    //               ::= [gs] nw <expression>* _ <type> <initializer>        # new (expr-list) type (init)
    //               ::= [gs] na <expression>* _ <type> E                    # new[] (expr-list) type
    //               ::= [gs] na <expression>* _ <type> <initializer>        # new[] (expr-list) type (init)
    //
    // <initializer> ::= pi <expression>* E                                  # parenthesized initialization
    private BaseNode parseNewExpression() {
        boolean isGlobal = consumeIf("gs");
        boolean isArray = peek(1) == 'a';

        if (!consumeIf("nw") || !consumeIf("na")) {
            return null;
        }

        List<BaseNode> expressions = new ArrayList<>();
        List<BaseNode> initializers = new ArrayList<>();

        while (!consumeIf("_")) {
            BaseNode expression = parseExpression();
            if (expression == null) {
                return null;
            }

            expressions.add(expression);
        }

        BaseNode typeNode = parseType();
        if (typeNode == null) {
            return null;
        }

        if (consumeIf("pi")) {
            while (!consumeIf("E")) {
                BaseNode initializer = parseExpression();
                if (initializer == null) {
                    return null;
                }

                initializers.add(initializer);
            }
        } else if (!consumeIf("E")) {
            return null;
        }

        return new NewExpression(new NodeArray(expressions), typeNode, new NodeArray(initializers), isGlobal, isArray);
    }


    // <expression> ::= <unary operator-name> <expression>
    //              ::= <binary operator-name> <expression> <expression>
    //              ::= <ternary operator-name> <expression> <expression> <expression>
    //              ::= pp_ <expression>                                     # prefix ++
    //              ::= mm_ <expression>                                     # prefix --
    //              ::= cl <expression>+ E                                   # expression (expr-list), call
    //              ::= cv <type> <expression>                               # type (expression), conversion with one argument
    //              ::= cv <type> _ <expression>* E                          # type (expr-list), conversion with other than one argument
    //              ::= tl <type> <braced-expression>* E                     # type {expr-list}, conversion with braced-init-list argument
    //              ::= il <braced-expression>* E                            # {expr-list}, braced-init-list in any other context
    //              ::= [gs] nw <expression>* _ <type> E                     # new (expr-list) type
    //              ::= [gs] nw <expression>* _ <type> <initializer>         # new (expr-list) type (init)
    //              ::= [gs] na <expression>* _ <type> E                     # new[] (expr-list) type
    //              ::= [gs] na <expression>* _ <type> <initializer>         # new[] (expr-list) type (init)
    //              ::= [gs] dl <expression>                                 # delete expression
    //              ::= [gs] da <expression>                                 # delete[] expression
    //              ::= dc <type> <expression>                               # dynamic_cast<type> (expression)
    //              ::= sc <type> <expression>                               # static_cast<type> (expression)
    //              ::= cc <type> <expression>                               # const_cast<type> (expression)
    //              ::= rc <type> <expression>                               # reinterpret_cast<type> (expression)
    //              ::= ti <type>                                            # typeid (type)
    //              ::= te <expression>                                      # typeid (expression)
    //              ::= st <type>                                            # sizeof (type)
    //              ::= sz <expression>                                      # sizeof (expression)
    //              ::= at <type>                                            # alignof (type)
    //              ::= az <expression>                                      # alignof (expression)
    //              ::= nx <expression>                                      # noexcept (expression)
    //              ::= <template-param>
    //              ::= <function-param>
    //              ::= dt <expression> <unresolved-name>                    # expr.name
    //              ::= pt <expression> <unresolved-name>                    # expr->name
    //              ::= ds <expression> <expression>                         # expr.*expr
    //              ::= sZ <template-param>                                  # sizeof...(T), size of a template parameter pack
    //              ::= sZ <function-param>                                  # sizeof...(parameter), size of a function parameter pack
    //              ::= sP <template-arg>* E                                 # sizeof...(T), size of a captured template parameter pack from an alias template
    //              ::= sp <expression>                                      # expression..., pack expansion
    //              ::= tw <expression>                                      # throw expression
    //              ::= tr                                                   # throw with no operand (rethrow)
    //              ::= <unresolved-name>                                    # f(p), N::f(p), ::f(p),
    //                                                                       # freestanding dependent name (e.g., T::x),
    //                                                                       # objectless nonstatic member reference
    //              ::= <expr-primary>
    private BaseNode parseExpression() {
        boolean isGlobal = consumeIf("gs");
        BaseNode expression;
        if (count() < 2) {
            return null;
        }

        switch (peek()) {
            case 'L':
                return parseExpressionPrimary();
            case 'T':
                return parseTemplateParam();
            case 'f':
                char c = peek(1);
                if (c == 'p' || (c == 'L' && Character.isDigit(peek(2)))) {
                    return parseFunctionParameter();
                }

                return parseFoldExpression();
            case 'a':
                switch (peek(1)) {
                    case 'a':
                        position += 2;
                        return parseBinaryExpression("&&");
                    case 'd':
                    case 'n':
                        position += 2;
                        return parseBinaryExpression("&");
                    case 'N':
                        position += 2;
                        return parseBinaryExpression("&=");
                    case 'S':
                        position += 2;
                        return parseBinaryExpression("=");
                    case 't':
                        position += 2;
                        BaseNode type = parseType();
                        if (type == null) {
                            return null;
                        }

                        return new EnclosedExpression("alignof (", type, ")");
                    case 'z':
                        position += 2;
                        expression = parseExpression();
                        if (expression == null) {
                            return null;
                        }

                        return new EnclosedExpression("alignof (", expression, ")");
                }
                return null;
            case 'c':
                switch (peek(1)) {
                    case 'c':
                        position += 2;
                        BaseNode to = parseType();
                        if (to == null) {
                            return null;
                        }

                        BaseNode from = parseExpression();
                        if (from == null) {
                            return null;
                        }

                        return new CastExpression("const_cast", to, from);
                    case 'l':
                        position += 2;
                        BaseNode callee = parseExpression();
                        if (callee == null) {
                            return null;
                        }

                        List<BaseNode> names = new ArrayList<>();
                        while (!consumeIf("E")) {
                            expression = parseExpression();
                            if (expression == null) {
                                return null;
                            }

                            names.add(expression);
                        }
                        return new CallExpression(callee, names);
                    case 'm':
                        position += 2;
                        return parseBinaryExpression(",");
                    case 'o':
                        position += 2;
                        return parsePrefixExpression("~");
                    case 'v':
                        return parseConversionExpression();
                }
                return null;
            case 'd':
                BaseNode leftNode;
                BaseNode rightNode;
                switch (peek(1)) {
                    case 'a':
                        position += 2;
                        expression = parseExpression();
                        if (expression == null) {
                            return null;
                        }

                        return new DeleteExpression(expression, isGlobal, true);
                    case 'c':
                        position += 2;
                        BaseNode type = parseType();
                        if (type == null) {
                            return null;
                        }

                        expression = parseExpression();
                        if (expression == null) {
                            return null;
                        }

                        return new CastExpression("dynamic_cast", type, expression);
                    case 'e':
                        position += 2;
                        return parsePrefixExpression("*");
                    case 'l':
                        position += 2;
                        expression = parseExpression();
                        if (expression == null) {
                            return null;
                        }

                        return new DeleteExpression(expression, isGlobal, false);
                    case 'n':
                        return parseUnresolvedName();
                    case 's':
                        position += 2;
                        leftNode = parseExpression();
                        if (leftNode == null) {
                            return null;
                        }

                        rightNode = parseExpression();
                        if (rightNode == null) {
                            return null;
                        }

                        return new MemberExpression(leftNode, ".*", rightNode);
                    case 't':
                        position += 2;
                        leftNode = parseExpression();
                        if (leftNode == null) {
                            return null;
                        }

                        rightNode = parseExpression();
                        if (rightNode == null) {
                            return null;
                        }

                        return new MemberExpression(leftNode, ".", rightNode);
                    case 'v':
                        position += 2;
                        return parseBinaryExpression("/");
                    case 'V':
                        position += 2;
                        return parseBinaryExpression("/=");
                }
                return null;
            case 'e':
                switch (peek(1)) {
                    case 'o':
                        position += 2;
                        return parseBinaryExpression("^");
                    case 'O':
                        position += 2;
                        return parseBinaryExpression("^=");
                    case 'q':
                        position += 2;
                        return parseBinaryExpression("==");
                }
                return null;
            case 'g':
                switch (peek(1)) {
                    case 'e':
                        position += 2;
                        return parseBinaryExpression(">=");
                    case 't':
                        position += 2;
                        return parseBinaryExpression(">");
                }
                return null;
            case 'i':
                switch (peek(1)) {
                    case 'x':
                        position += 2;
                        BaseNode baseNode = parseExpression();
                        if (baseNode == null) {
                            return null;
                        }

                        BaseNode subscript = parseExpression();

                        return new ArraySubscriptingExpression(baseNode, subscript);
                    case 'l':
                        position += 2;

                        List<BaseNode> bracedExpressions = new ArrayList<>();
                        while (!consumeIf("E")) {
                            expression = parseBracedExpression();
                            if (expression == null) {
                                return null;
                            }

                            bracedExpressions.add(expression);
                        }
                        return new InitListExpression(null, bracedExpressions);
                }
                return null;
            case 'l':
                switch (peek(1)) {
                    case 'e':
                        position += 2;
                        return parseBinaryExpression("<=");
                    case 's':
                        position += 2;
                        return parseBinaryExpression("<<");
                    case 'S':
                        position += 2;
                        return parseBinaryExpression("<<=");
                    case 't':
                        position += 2;
                        return parseBinaryExpression("<");
                }
                return null;
            case 'm':
                switch (peek(1)) {
                    case 'i':
                        position += 2;
                        return parseBinaryExpression("-");
                    case 'I':
                        position += 2;
                        return parseBinaryExpression("-=");
                    case 'l':
                        position += 2;
                        return parseBinaryExpression("*");
                    case 'L':
                        position += 2;
                        return parseBinaryExpression("*=");
                    case 'm':
                        position += 2;
                        if (consumeIf("_")) {
                            return parsePrefixExpression("--");
                        }

                        expression = parseExpression();
                        if (expression == null) {
                            return null;
                        }

                        return new PostfixExpression(expression, "--");
                }
                return null;
            case 'n':
                switch (peek(1)) {
                    case 'a':
                    case 'w':
                        position += 2;
                        return parseNewExpression();
                    case 'e':
                        position += 2;
                        return parseBinaryExpression("!=");
                    case 'g':
                        position += 2;
                        return parsePrefixExpression("-");
                    case 't':
                        position += 2;
                        return parsePrefixExpression("!");
                    case 'x':
                        position += 2;
                        expression = parseExpression();
                        if (expression == null) {
                            return null;
                        }

                        return new EnclosedExpression("noexcept (", expression, ")");
                }
                return null;
            case 'o':
                switch (peek(1)) {
                    case 'n':
                        return parseUnresolvedName();
                    case 'o':
                        position += 2;
                        return parseBinaryExpression("||");
                    case 'r':
                        position += 2;
                        return parseBinaryExpression("|");
                    case 'R':
                        position += 2;
                        return parseBinaryExpression("|=");
                }
                return null;
            case 'p':
                switch (peek(1)) {
                    case 'm':
                        position += 2;
                        return parseBinaryExpression("->*");
                    case 'l':
                    case 's':
                        position += 2;
                        return parseBinaryExpression("+");
                    case 'L':
                        position += 2;
                        return parseBinaryExpression("+=");
                    case 'p':
                        position += 2;
                        if (consumeIf("_")) {
                            return parsePrefixExpression("++");
                        }

                        expression = parseExpression();
                        if (expression == null) {
                            return null;
                        }

                        return new PostfixExpression(expression, "++");
                    case 't':
                        position += 2;
                        leftNode = parseExpression();
                        if (leftNode == null) {
                            return null;
                        }

                        rightNode = parseExpression();
                        if (rightNode == null) {
                            return null;
                        }

                        return new MemberExpression(leftNode, "->", rightNode);
                }
                return null;
            case 'q':
                if (peek(1) == 'u') {
                    position += 2;
                    BaseNode condition = parseExpression();
                    if (condition == null) {
                        return null;
                    }

                    leftNode = parseExpression();
                    if (leftNode == null) {
                        return null;
                    }

                    rightNode = parseExpression();
                    if (rightNode == null) {
                        return null;
                    }

                    return new ConditionalExpression(condition, leftNode, rightNode);
                }
                return null;
            case 'r':
                switch (peek(1)) {
                    case 'c':
                        position += 2;
                        BaseNode to = parseType();
                        if (to == null) {
                            return null;
                        }

                        BaseNode from = parseExpression();
                        if (from == null) {
                            return null;
                        }

                        return new CastExpression("reinterpret_cast", to, from);
                    case 'm':
                    case 'M':
                        position += 2;
                        return parseBinaryExpression("%");
                    case 's':
                        position += 2;
                        return parseBinaryExpression(">>");
                    case 'S':
                        position += 2;
                        return parseBinaryExpression(">>=");
                }
                return null;
            case 's':
                switch (peek(1)) {
                    case 'c':
                        position += 2;
                        BaseNode to = parseType();
                        if (to == null) {
                            return null;
                        }

                        BaseNode from = parseExpression();
                        if (from == null) {
                            return null;
                        }

                        return new CastExpression("static_cast", to, from);
                    case 'p':
                        position += 2;
                        expression = parseExpression();
                        if (expression == null) {
                            return null;
                        }

                        return new PackedTemplateParameterExpansion(expression);
                    case 'r':
                        return parseUnresolvedName();
                    case 't':
                        position += 2;
                        BaseNode enclosedType = parseType();
                        if (enclosedType == null) {
                            return null;
                        }

                        return new EnclosedExpression("sizeof (", enclosedType, ")");
                    case 'z':
                        position += 2;
                        expression = parseExpression();
                        if (expression == null) {
                            return null;
                        }

                        return new EnclosedExpression("sizeof (", expression, ")");
                    case 'Z':
                        position += 2;
                        BaseNode sizeofParamNode;
                        switch (peek()) {
                            case 'T':
                                // FIXME: ??? Not entire sure if it's right
                                sizeofParamNode = parseFunctionParameter();
                                if (sizeofParamNode == null) {
                                    return null;
                                }

                                return new EnclosedExpression("sizeof...(", new PackedTemplateParameterExpansion(sizeofParamNode), ")");
                            case 'f':
                                sizeofParamNode = parseFunctionParameter();
                                if (sizeofParamNode == null) {
                                    return null;
                                }

                                return new EnclosedExpression("sizeof...(", sizeofParamNode, ")");
                        }
                        return null;
                    case 'P':
                        position += 2;
                        List<BaseNode> arguments = new ArrayList<>();
                        while (!consumeIf("E")) {
                            BaseNode argument = parseTemplateArgument();
                            if (argument == null) {
                                return null;
                            }

                            arguments.add(argument);
                        }
                        return new EnclosedExpression("sizeof...(", new NodeArray(arguments), ")");
                }
                return null;
            case 't':
                switch (peek(1)) {
                    case 'e':
                        expression = parseExpression();
                        if (expression == null) {
                            return null;
                        }

                        return new EnclosedExpression("typeid (", expression, ")");
                    case 't':
                        BaseNode enclosedType = parseExpression();
                        if (enclosedType == null) {
                            return null;
                        }

                        return new EnclosedExpression("typeid (", enclosedType, ")");
                    case 'l':
                        position += 2;
                        BaseNode typeNode = parseType();
                        if (typeNode == null) {
                            return null;
                        }

                        List<BaseNode> bracedExpressions = new ArrayList<>();
                        while (!consumeIf("E")) {
                            expression = parseBracedExpression();
                            if (expression == null) {
                                return null;
                            }

                            bracedExpressions.add(expression);
                        }
                        return new InitListExpression(typeNode, bracedExpressions);
                    case 'r':
                        position += 2;
                        return new NameType("throw");
                    case 'w':
                        position += 2;
                        expression = parseExpression();
                        if (expression == null) {
                            return null;
                        }

                        return new ThrowExpression(expression);
                }
                return null;
        }

        if (Character.isDigit(peek())) {
            return parseUnresolvedName();
        }

        return null;
    }

    private BaseNode parseIntegerLiteral(String literalName) {
        String number = parseNumber(true);
        if (number == null || number.length() == 0 || !consumeIf("E")) {
            return null;
        }

        return new IntegerLiteral(literalName, number);
    }

    // <expr-primary> ::= L <type> <value number> E                          # integer literal
    //                ::= L <type> <value float> E                           # floating literal (TODO)
    //                ::= L <String type> E                                  # String literal
    //                ::= L <nullptr type> E                                 # nullptr literal (i.e., "LDnE")
    //                ::= L <pointer type> 0 E                               # null pointer template argument
    //                ::= L <type> <real-part float> _ <imag-part float> E   # complex floating point literal (C 2000)
    //                ::= L _Z <encoding> E                                  # external name
    private BaseNode parseExpressionPrimary() {
        if (!consumeIf("L")) {
            return null;
        }

        switch (peek()) {
            case 'w':
                position++;
                return parseIntegerLiteral("wchar_t");
            case 'b':
                if (consumeIf("b0E")) {
                    return new NameType("false", NodeType.BooleanExpression);
                }

                if (consumeIf("b1E")) {
                    return new NameType("true", NodeType.BooleanExpression);
                }

                return null;
            case 'c':
                position++;
                return parseIntegerLiteral("char");
            case 'a':
                position++;
                return parseIntegerLiteral("signed char");
            case 'h':
                position++;
                return parseIntegerLiteral("unsigned char");
            case 's':
                position++;
                return parseIntegerLiteral("short");
            case 't':
                position++;
                return parseIntegerLiteral("unsigned short");
            case 'i':
                position++;
                return parseIntegerLiteral("");
            case 'j':
                position++;
                return parseIntegerLiteral("u");
            case 'l':
                position++;
                return parseIntegerLiteral("l");
            case 'm':
                position++;
                return parseIntegerLiteral("ul");
            case 'x':
                position++;
                return parseIntegerLiteral("ll");
            case 'y':
                position++;
                return parseIntegerLiteral("ull");
            case 'n':
                position++;
                return parseIntegerLiteral("__int128");
            case 'o':
                position++;
                return parseIntegerLiteral("unsigned __int128");
            case 'd':
            case 'e':
            case 'f':
                // TODO: floating literal
                return null;
            case '_':
                if (consumeIf("_Z")) {
                    BaseNode encoding = parseEncoding();
                    if (encoding != null && consumeIf("E")) {
                        return encoding;
                    }
                }
                return null;
            case 'T':
                return null;
            default:
                BaseNode type = parseType();
                if (type == null) {
                    return null;
                }

                String number = parseNumber();
                if (number == null || number.length() == 0 || !consumeIf("E")) {
                    return null;
                }

                return new IntegerCastExpression(type, number);
        }
    }

    // <decltype>  ::= Dt <expression> E  # decltype of an id-expression or class member access (C++0x)
    //             ::= DT <expression> E  # decltype of an expression (C++0x)
    private BaseNode parseDecltype() {
        if (!consumeIf("D") || (!consumeIf("t") && !consumeIf("T"))) {
            return null;
        }

        BaseNode expression = parseExpression();
        if (expression == null) {
            return null;
        }

        if (!consumeIf("E")) {
            return null;
        }

        return new EnclosedExpression("decltype(", expression, ")");
    }

    // <template-param>          ::= T_ # first template parameter
    //                           ::= T <parameter-2 non-negative number> _
    // <template-template-param> ::= <template-param>
    //                           ::= <substitution>
    private BaseNode parseTemplateParam() {
        if (!consumeIf("T")) {
            return null;
        }

        int index = 0;
        if (!consumeIf("_")) {
            index = parsePositiveNumber();
            if (index < 0) {
                return null;
            }

            index++;
            if (!consumeIf("_")) {
                return null;
            }
        }

        // 5.1.8: TODO: lambda?
        // if (IsParsingLambdaParameters)
        //    return new de.fearlesstobi.demangler.ast.NameType("auto");

        if (canForwardTemplateReference) {
            return new ForwardTemplateReference();
        }
        if (index >= templateParamList.size()) {
            return null;
        }

        return templateParamList.get(index);
    }

    // <template-args> ::= I <template-arg>+ E
    private BaseNode parseTemplateArguments() {
        return parseTemplateArguments(false);
    }

    // <template-args> ::= I <template-arg>+ E
    private BaseNode parseTemplateArguments(boolean hasContext) {
        if (!consumeIf("I")) {
            return null;
        }

        if (hasContext) {
            templateParamList.clear();
        }

        List<BaseNode> args = new ArrayList<>();
        while (!consumeIf("E")) {
            if (hasContext) {
                List<BaseNode> templateParamListTemp = new ArrayList<>(templateParamList);
                BaseNode templateArgument = parseTemplateArgument();
                templateParamList = templateParamListTemp;
                if (templateArgument == null) {
                    return null;
                }

                args.add(templateArgument);
                if (templateArgument.type == NodeType.PackedTemplateArgument) {
                    templateArgument = new PackedTemplateParameter(((NodeArray) templateArgument).nodes);
                }
                templateParamList.add(templateArgument);
            } else {
                BaseNode templateArgument = parseTemplateArgument();
                if (templateArgument == null) {
                    return null;
                }

                args.add(templateArgument);
            }
        }
        return new TemplateArguments(args);
    }


    // <template-arg> ::= <type>                                             # type or template
    //                ::= X <expression> E                                   # expression
    //                ::= <expr-primary>                                     # simple expressions
    //                ::= J <template-arg>* E                                # argument pack
    private BaseNode parseTemplateArgument() {
        switch (peek()) {
            // X <expression> E
            case 'X':
                position++;
                BaseNode expression = parseExpression();
                if (expression == null || !consumeIf("E")) {
                    return null;
                }

                return expression;
            // <expr-primary>
            case 'L':
                return parseExpressionPrimary();
            // J <template-arg>* E
            case 'J':
                position++;
                List<BaseNode> templateArguments = new ArrayList<>();
                while (!consumeIf("E")) {
                    BaseNode templateArgument = parseTemplateArgument();
                    if (templateArgument == null) {
                        return null;
                    }

                    templateArguments.add(templateArgument);
                }
                return new NodeArray(templateArguments, NodeType.PackedTemplateArgument);
            // <type>
            default:
                return parseType();
        }
    }

    class NameparserContext {
        CvType cvType;
        SimpleReferenceType ref;
        boolean finishWithTemplateArguments;
        boolean ctorDtorConversion;
    }


    //   <unresolved-type> ::= <template-param> [ <template-args> ]            # T:: or T<X,Y>::
    //                     ::= <decltype>                                      # decltype(p)::
    //                     ::= <substitution>
    private BaseNode parseUnresolvedType() {
        if (peek() == 'T') {
            BaseNode templateParam = parseTemplateParam();
            if (templateParam == null) {
                return null;
            }

            substitutionList.add(templateParam);
            return templateParam;
        } else if (peek() == 'D') {
            BaseNode declType = parseDecltype();
            if (declType == null) {
                return null;
            }

            substitutionList.add(declType);
            return declType;
        }
        return parseSubstitution();
    }

    // <simple-id> ::= <source-name> [ <template-args> ]
    private BaseNode parseSimpleId() {
        BaseNode sourceName = parseSourceName();
        if (sourceName == null) {
            return null;
        }

        if (peek() == 'I') {
            BaseNode templateArguments = parseTemplateArguments();
            if (templateArguments == null) {
                return null;
            }

            return new NameTypeWithTemplateArguments(sourceName, templateArguments);
        }
        return sourceName;
    }

    //  <destructor-name> ::= <unresolved-type>                               # e.g., ~T or ~decltype(f())
    //                    ::= <simple-id>                                     # e.g., ~A<2*N>
    private BaseNode parseDestructorName() {
        BaseNode node;
        if (Character.isDigit(peek())) {
            node = parseSimpleId();
        } else {
            node = parseUnresolvedType();
        }
        if (node == null) {
            return null;
        }

        return new DtorName(node);
    }

    //  <base-unresolved-name> ::= <simple-id>                                # unresolved name
    //  extension              ::= <operator-name>                            # unresolved operator-function-id
    //  extension              ::= <operator-name> <template-args>            # unresolved operator template-id
    //                         ::= on <operator-name>                         # unresolved operator-function-id
    //                         ::= on <operator-name> <template-args>         # unresolved operator template-id
    //                         ::= dn <destructor-name>                       # destructor or pseudo-destructor;
    //                                                                        # e.g. ~X or ~X<N-1>
    private BaseNode parseBaseUnresolvedName() {
        if (Character.isDigit(peek())) {
            return parseSimpleId();
        } else if (consumeIf("dn")) {
            return parseDestructorName();
        }

        consumeIf("on");
        BaseNode operatorName = parseOperatorName(null);
        if (operatorName == null) {
            return null;
        }

        if (peek() == 'I') {
            BaseNode templateArguments = parseTemplateArguments();
            if (templateArguments == null) {
                return null;
            }

            return new NameTypeWithTemplateArguments(operatorName, templateArguments);
        }
        return operatorName;
    }

    // <unresolved-name> ::= [gs] <base-unresolved-name>                     # x or (with "gs") ::x
    //                   ::= sr <unresolved-type> <base-unresolved-name>     # T::x / decltype(p)::x
    //                   ::= srN <unresolved-type> <unresolved-qualifier-level>+ E <base-unresolved-name>
    //                                                                       # T::N::x /decltype(p)::N::x
    //                   ::= [gs] sr <unresolved-qualifier-level>+ E <base-unresolved-name>
    //                                                                       # A::x, N::y, A<T>::z; "gs" means leading "::"
    private BaseNode parseUnresolvedName() {
        BaseNode result = null;
        if (consumeIf("srN")) {
            result = parseUnresolvedType();
            if (result == null) {
                return null;
            }

            if (peek() == 'I') {
                BaseNode templateArguments = parseTemplateArguments();
                if (templateArguments == null) {
                    return null;
                }

                result = new NameTypeWithTemplateArguments(result, templateArguments);
            }

            while (!consumeIf("E")) {
                BaseNode simpleId = parseSimpleId();
                if (simpleId == null) {
                    return null;
                }

                result = new QualifiedName(result, simpleId);
            }

            BaseNode baseName = parseBaseUnresolvedName();
            if (baseName == null) {
                return null;
            }

            return new QualifiedName(result, baseName);
        }

        boolean isGlobal = consumeIf("gs");

        // ::= [gs] <base-unresolved-name>                     # x or (with "gs") ::x
        if (!consumeIf("sr")) {
            result = parseBaseUnresolvedName();
            if (result == null) {
                return null;
            }

            if (isGlobal) {
                result = new GlobalQualifiedName(result);
            }

            return result;
        }

        // ::= [gs] sr <unresolved-qualifier-level>+ E <base-unresolved-name>
        if (Character.isDigit(peek())) {
            do {
                BaseNode qualifier = parseSimpleId();
                if (qualifier == null) {
                    return null;
                }

                if (result != null) {
                    result = new QualifiedName(result, qualifier);
                } else if (isGlobal) {
                    result = new GlobalQualifiedName(qualifier);
                } else {
                    result = qualifier;
                }

            } while (!consumeIf("E"));
        }
        // ::= sr <unresolved-type> [template-args] <base-unresolved-name>     # T::x / decltype(p)::x
        else {
            result = parseUnresolvedType();
            if (result == null) {
                return null;
            }

            if (peek() == 'I') {
                BaseNode templateArguments = parseTemplateArguments();
                if (templateArguments == null) {
                    return null;
                }

                result = new NameTypeWithTemplateArguments(result, templateArguments);
            }
        }

        BaseNode baseUnresolvedName = parseBaseUnresolvedName();
        if (baseUnresolvedName == null) {
            return null;
        }

        return new QualifiedName(result, baseUnresolvedName);
    }

    //    <unscoped-name> ::= <unqualified-name>
    //                    ::= St <unqualified-name>   # ::std::
    private BaseNode parseUnscopedName() {
        if (consumeIf("St")) {
            BaseNode unresolvedName = parseUnresolvedName();
            if (unresolvedName == null) {
                return null;
            }

            return new StdQualifiedName(unresolvedName);
        }
        return parseUnresolvedName();
    }

    // <nested-name> ::= N [<CV-qualifiers>] [<ref-qualifier>] <prefix (TODO)> <unqualified-name> E
    //               ::= N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix (TODO)> <template-args (TODO)> E
    private BaseNode parseNestedName(NameparserContext context) {
        // Impossible in theory
        if (consume() != 'N') {
            return null;
        }

        BaseNode result = null;
        CvType cv = new CvType(parseCvQualifiers(), null);
        if (context != null) {
            context.cvType = cv;
        }

        SimpleReferenceType ref = parseRefQualifiers();
        if (context != null) {
            context.ref = ref;
        }

        if (consumeIf("St")) {
            result = new NameType("std");
        }

        while (!consumeIf("E")) {
            // <data-member-prefix> end
            if (consumeIf("M")) {
                if (result == null) {
                    return null;
                }

                continue;
            }
            char c = peek();

            // TODO: template args
            if (c == 'T') {
                BaseNode templateParam = parseTemplateParam();
                if (templateParam == null) {
                    return null;
                }

                result = createNameNode(result, templateParam, context);
                substitutionList.add(result);
                continue;
            }

            // <template-prefix> <template-args>
            if (c == 'I') {
                BaseNode templateArgument = parseTemplateArguments(context != null);
                if (templateArgument == null || result == null) {
                    return null;
                }

                result = new NameTypeWithTemplateArguments(result, templateArgument);
                if (context != null) {
                    context.finishWithTemplateArguments = true;
                }

                substitutionList.add(result);
                continue;
            }

            // <decltype>
            if (c == 'D' && (peek(1) == 't' || peek(1) == 'T')) {
                BaseNode decltype = parseDecltype();
                if (decltype == null) {
                    return null;
                }

                result = createNameNode(result, decltype, context);
                substitutionList.add(result);
                continue;
            }

            // <substitution>
            if (c == 'S' && peek(1) != 't') {
                BaseNode substitution = parseSubstitution();
                if (substitution == null) {
                    return null;
                }

                result = createNameNode(result, substitution, context);
                if (result != substitution) {
                    substitutionList.add(substitution);
                }

                continue;
            }

            // <ctor-dtor-name> of parseUnqualifiedName
            if (c == 'C' || (c == 'D' && peek(1) != 'C')) {
                // We cannot have nothing before this
                if (result == null) {
                    return null;
                }

                BaseNode ctOrDtorName = parseCtorDtorName(context, result);

                if (ctOrDtorName == null) {
                    return null;
                }

                result = createNameNode(result, ctOrDtorName, context);

                // TODO: ABI Tags (before)
                if (result == null) {
                    return null;
                }

                substitutionList.add(result);
                continue;
            }

            BaseNode unqualifiedName = parseUnqualifiedName(context);
            if (unqualifiedName == null) {
                return null;
            }
            result = createNameNode(result, unqualifiedName, context);

            substitutionList.add(result);
        }
        if (result == null || substitutionList.size() == 0) {
            return null;
        }

        substitutionList.remove(substitutionList.size() - 1);
        return result;
    }

    //   <discriminator> ::= _ <non-negative number>      # when number < 10
    //                   ::= __ <non-negative number> _   # when number >= 10
    private void parseDiscriminator() {
        if (count() == 0) {
            return;
        }
        // We ignore the discriminator, we don't need it.
        if (consumeIf("_")) {
            consumeIf("_");
            while (Character.isDigit(peek()) && count() != 0) {
                consume();
            }
            consumeIf("_");
        }
    }

    //   <local-name> ::= Z <function encoding> E <entity name> [<discriminator>]
    //                ::= Z <function encoding> E s [<discriminator>]
    //                ::= Z <function encoding> Ed [ <parameter number> ] _ <entity name>
    private BaseNode parseLocalName(NameparserContext context) {
        if (!consumeIf("Z")) {
            return null;
        }

        BaseNode encoding = parseEncoding();
        if (encoding == null || !consumeIf("E")) {
            return null;
        }

        BaseNode entityName;
        if (consumeIf("s")) {
            parseDiscriminator();
            return new LocalName(encoding, new NameType("String literal"));
        } else if (consumeIf("d")) {
            parseNumber(true);
            if (!consumeIf("_")) {
                return null;
            }

            entityName = parseName(context);
            if (entityName == null) {
                return null;
            }

            return new LocalName(encoding, entityName);
        }

        entityName = parseName(context);
        if (entityName == null) {
            return null;
        }

        parseDiscriminator();
        return new LocalName(encoding, entityName);
    }

    private BaseNode parseName() {
        return parseName(null);
    }

    // <name> ::= <nested-name>
    //        ::= <unscoped-name>
    //        ::= <unscoped-template-name> <template-args>
    //        ::= <local-name>  # See Scope Encoding below (TODO)
    private BaseNode parseName(NameparserContext context) {
        consumeIf("L");

        if (peek() == 'N') {
            return parseNestedName(context);
        }

        if (peek() == 'Z') {
            return parseLocalName(context);
        }

        if (peek() == 'S' && peek(1) != 't') {
            BaseNode substitution = parseSubstitution();
            if (substitution == null) {
                return null;
            }

            if (peek() != 'I') {
                return null;
            }

            BaseNode templateArguments = parseTemplateArguments(context != null);
            if (templateArguments == null) {
                return null;
            }

            if (context != null) {
                context.finishWithTemplateArguments = true;
            }

            return new NameTypeWithTemplateArguments(substitution, templateArguments);
        }

        BaseNode result = parseUnscopedName();
        if (result == null) {
            return null;
        }

        if (peek() == 'I') {
            substitutionList.add(result);
            BaseNode templateArguments = parseTemplateArguments(context != null);
            if (templateArguments == null) {
                return null;
            }

            if (context != null) {
                context.finishWithTemplateArguments = true;
            }

            return new NameTypeWithTemplateArguments(result, templateArguments);
        }

        return result;
    }

    private boolean isEncodingEnd() {
        char c = peek();
        return count() == 0 || c == 'E' || c == '.' || c == '_';
    }

    // <encoding> ::= <function name> <bare-function-type>
    //            ::= <data name>
    //            ::= <special-name>
    private BaseNode parseEncoding() {
        NameparserContext context = new NameparserContext();
        if (peek() == 'T' || (peek() == 'G' && peek(1) == 'V')) {
            return parseSpecialName(context);
        }

        BaseNode name = parseName(context);
        if (name == null) {
            return null;
        }

        // TODO: compute template refs here

        if (isEncodingEnd()) {
            return name;
        }

        // TODO: Ua9enable_ifI

        BaseNode returnType = null;
        if (!context.ctorDtorConversion && context.finishWithTemplateArguments) {
            returnType = parseType();
            if (returnType == null) {
                return null;
            }
        }

        if (consumeIf("v")) {
            return new EncodedFunction(name, null, context.cvType, context.ref, null, returnType);
        }

        List<BaseNode> params = new ArrayList<>();

        // backup because that can be destroyed by parseType
        CvType cv = context.cvType;
        SimpleReferenceType ref = context.ref;

        while (!isEncodingEnd()) {
            BaseNode param = parseType();
            if (param == null) {
                return null;
            }

            params.add(param);
        }

        return new EncodedFunction(name, new NodeArray(params), cv, ref, null, returnType);
    }

    // <mangled-name> ::= _Z <encoding>
    //                ::= <type>
    private BaseNode parse() {
        if (consumeIf("_Z")) {
            BaseNode encoding = parseEncoding();
            if (encoding != null && count() == 0) {
                return encoding;
            }
            return null;
        } else {
            BaseNode type = parseType();
            if (type != null && count() == 0) {
                return type;
            }
            return null;
        }
    }

    public static String parse(String originalMangled) {
        Demangler instance = new Demangler(originalMangled);
        BaseNode resNode = instance.parse();

        if (resNode != null) {
            StringWriter writer = new StringWriter();
            resNode.print(writer);
            return writer.toString();
        }

        return originalMangled;
    }
}
