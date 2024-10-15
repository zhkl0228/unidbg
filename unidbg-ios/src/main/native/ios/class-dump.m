//
//  class-dump.m
//  runtime_class-dump
//
//  Created by Asger Hautop Drewsen on 5/6/14.
//  Copyright (c) 2014 Tyilo. All rights reserved.
//

#import "class-dump.h"
#include <objc/runtime.h>
#include <dlfcn.h>

static bool matchesSuper(Class class, const char *keywords) {
  if(class) {
    const char *className = class_getName(class);
    if(strcmp(className, keywords) == 0) {
      return true;
    }
    return matchesSuper(class_getSuperclass(class), keywords);
  } else {
    return false;
  }
}

@implementation ClassDump

NSUInteger findClosedBracket(NSString *string) {
	NSUInteger length = [string length];
	NSUInteger i = 0;
	NSUInteger depth = 0;
	BOOL foundFirst = NO;
	while((!foundFirst || depth > 0) && i < length) {
		char c = [string characterAtIndex:i];
		switch(c) {
			case '(':
			case '[':
			case '{':
				depth++;
				foundFirst = YES;
				break;
			case ')':
			case ']':
			case '}':
				depth--;
				break;
		}
		
		i++;
	}
	
	return i - 1;
}

#define COMPARE_ENC_CUSTOM(var, type) do { \
	if(var == @encode(type)[0]) { \
		return @#type; \
	} \
} while(0)

#define COMPARE_ENC(type) COMPARE_ENC_CUSTOM(firstChar, type)

+(NSString *) basicTypeFromEncoding: (const char *) encoding {
	char firstChar = encoding[0];
	
	COMPARE_ENC(char);
	COMPARE_ENC(int);
	COMPARE_ENC(short);
	COMPARE_ENC(long);
	COMPARE_ENC(long long);
	COMPARE_ENC(unsigned char);
	COMPARE_ENC(unsigned int);
	COMPARE_ENC(unsigned short);
	COMPARE_ENC(unsigned long);
	COMPARE_ENC(unsigned long long);
	COMPARE_ENC(float);
	COMPARE_ENC(double);
	COMPARE_ENC(_Bool);
	COMPARE_ENC(void);
	COMPARE_ENC(char *);
	COMPARE_ENC(id);
	COMPARE_ENC(Class);
	COMPARE_ENC(SEL);
	
	if(encoding[0] == '?') {
		return @"void *";
	}
	
	return nil;
}

+(NSArray *) typeStringFromEncoding: (const char *) typeEncoding end: (NSUInteger *) end {
	if(typeEncoding[0] == '\0') {
		return @[@"void", @""];
	}
	
	NSDictionary *qualifiers = @{
		@"r": @"const",
		@"n": @"in",
		@"N": @"inout",
		@"o": @"out",
		@"O": @"bycopy",
		@"R": @"byref",
		@"V": @"oneway"
	};
	
	NSUInteger dummy;
	if(!end) {
		end = &dummy;
	}
	
	NSMutableString *typePrefix = [NSMutableString new];
	NSMutableString *typeSuffix = [NSMutableString new];
	
	NSString *typeEnc = [NSString stringWithUTF8String:typeEncoding];
	
	BOOL isArray = [typeEnc hasPrefix:@"["];
	BOOL isStruct = [typeEnc hasPrefix:@"{"];
	BOOL isUnion = [typeEnc hasPrefix:@"("];
	
	NSString *qualifier = qualifiers[[typeEnc substringToIndex:1]];
	
	if(isArray || isStruct || isUnion) {
		NSUInteger endOfBracket = findClosedBracket(typeEnc);
		
		if(isArray) {
			NSScanner *scanner = [NSScanner scannerWithString:typeEnc];
			scanner.scanLocation = 1;
			int size;
			assert([scanner scanInt:&size]);
			
			[typeSuffix appendFormat:@"[%d]", size];
			
			NSString *inner = [typeEnc substringWithRange:NSMakeRange(scanner.scanLocation, endOfBracket - scanner.scanLocation)];
			NSUInteger innerEnd;
			NSArray *innerType = [ClassDump typeStringFromEncoding: [inner UTF8String] end: &innerEnd];
			
			assert(scanner.scanLocation + innerEnd == endOfBracket);
			
			[typePrefix appendString:innerType[0]];
			[typeSuffix appendString:innerType[1]];
		} else {
			NSString *name;
			
			[typePrefix appendString:isStruct? @"struct ": @"union "];
			
			const char *equals = strchr(typeEncoding, '=');
			unsigned long index = 0;
			
			if(!equals) {
				name = [typeEnc substringWithRange:NSMakeRange(1, endOfBracket - 1)];
			} else {
				index = equals - typeEncoding;
				
				name = [typeEnc substringWithRange:NSMakeRange(1, index - 1)];
			}
			
			if(![name isEqualToString:@"?"]) {
				[typePrefix appendFormat:@"%@ ", name];
			}
			
			const char *ptr = typeEncoding + index + 1;
			
			if(equals && ptr - typeEncoding < (int) endOfBracket) {
				[typePrefix appendString:@"{ "];
				
				int fieldIndex = 0;
				
				while(ptr - typeEncoding < (int) endOfBracket) {
					NSString *fieldName = [NSString stringWithFormat:@"field%d", fieldIndex];
					
					if(*ptr == '"') {
						ptr++;
						char *fieldNameEnd = strchr(ptr, '"');
						assert(fieldNameEnd);
						
						fieldName = [[NSString alloc] initWithBytes:ptr length:(fieldNameEnd - ptr) encoding:NSUTF8StringEncoding];
						
						ptr = fieldNameEnd + 1;
					}
					
					NSUInteger fieldEnd;
					NSArray *fieldType = [ClassDump typeStringFromEncoding: ptr end: &fieldEnd];
					[typePrefix appendFormat:@"%@ %@%@; ", fieldType[0], fieldName, fieldType[1]];
					
					fieldIndex++;
					ptr += fieldEnd;
				}
				
				[typePrefix appendString:@"}"];
			}
		}
		
		*end = endOfBracket + 1;
		
	} else if([typeEnc hasPrefix:@"b"]) {
		NSScanner *scanner = [NSScanner scannerWithString:typeEnc];
		scanner.scanLocation = 1;
		int size;
		assert([scanner scanInt:&size]);
		
		[typePrefix appendString:@"unsigned long long"];
		[typeSuffix appendFormat:@":%d", size];
		
		*end = scanner.scanLocation;
	} else if([typeEnc hasPrefix:@"^"]) {
		*end = 0;
		
		while(typeEncoding[0] == '^') {
			[typePrefix appendString:@"*"];
			typeEncoding++;
			(*end)++;
		}
		
		NSUInteger pointerEnd;
		NSArray *pointerType = [ClassDump typeStringFromEncoding: typeEncoding end: &pointerEnd];
		
		NSString *str = pointerType[1];
		if(![str isEqualToString:@""]) {
			[typePrefix insertString:@"(" atIndex:0];
			[typeSuffix appendString:@") "];
			[typeSuffix appendString:str];
		}
		
		[typePrefix insertString:pointerType[0] atIndex:0];
		
		*end += pointerEnd;
	} else if(qualifier) {
		[typePrefix appendFormat:@"%@ ", qualifier];
		
		NSUInteger realEnd;
		NSArray *realType = [ClassDump typeStringFromEncoding: typeEncoding + 1 end: &realEnd];
		
		[typePrefix appendString:realType[0]];
		[typeSuffix appendString:realType[1]];
		
		*end = realEnd + 1;
	} else if([typeEnc hasPrefix:@"\""]) {
		// This occurs sometimes, but I forgot what to do :/
		assert(0);
	} else {
		NSString *basicType = [ClassDump basicTypeFromEncoding: typeEncoding];
		//assert(basicType);
		if(!basicType) {
			NSLog(@"%s", typeEncoding);
			basicType = @"void *";
		}
		
		if([basicType isEqualToString:@"id"] && typeEncoding[1] == '"') {
			const char *ptr = typeEncoding + 1;
			ptr++;
			char *classNameEnd = strchr(ptr, '"');
			assert(classNameEnd);
			
			NSString *className = [[NSString alloc] initWithBytes:ptr length:(classNameEnd - ptr) encoding:NSUTF8StringEncoding];
				
			[typePrefix insertString:[NSString stringWithFormat:@"%@ *", className] atIndex:0];
			
			*end = classNameEnd - typeEncoding + 1;
		} else {
			[typePrefix insertString:basicType atIndex:0];
			*end = 1;
		}
	}
	
	return @[typePrefix, typeSuffix];
}

+(NSString *) variableDefinitionWithName: (const char *) typeEncoding name: (const char *) name {
	NSArray *typeString = [ClassDump typeStringFromEncoding: typeEncoding end: NULL];
	return [NSString stringWithFormat:@"%@ %s%@;", typeString[0], name, typeString[1]];
}

+(NSString *) methodArgTypeString: (const char *) typeEncoding {
	NSArray *typeString = [ClassDump typeStringFromEncoding: typeEncoding end: NULL];
	return [typeString componentsJoinedByString:@""];
}

+(NSString *) class_dump_class: (Class) class {
	NSMutableString *result = [NSMutableString new];
	
	const char *className = class_getName(class);
	
	[result appendFormat:@"@interface %s", className];
	
	Class superclass = class_getSuperclass(class);
	if(superclass) {
		const char *superClassName = class_getName(superclass);
		[result appendFormat:@" : %s", superClassName];
	}
	
	unsigned int protocolCount;
	Protocol *__unsafe_unretained *protocols = class_copyProtocolList(class, &protocolCount);
	
	if(protocols) {
		if(protocolCount > 0) {
			[result appendString:@" <"];
			for(unsigned int i = 0; i < protocolCount; i++) {
				const char *protocolName = protocol_getName(protocols[i]);
				[result appendFormat:@"%s%s", (i == 0? "": ", "), protocolName];
			}
			[result appendString:@">"];
		}
		
		free(protocols);
	}
	
	unsigned int ivarCount;
	Ivar *ivars = class_copyIvarList(class, &ivarCount);
	
	if(ivars) {
		if(ivarCount > 0) {
			[result appendString:@" {\n"];
			
			for(unsigned int i = 0; i < ivarCount; i++) {
				Ivar ivar = ivars[i];
				const char *ivarName = ivar_getName(ivar);
				const char *ivarTypeEncoding = ivar_getTypeEncoding(ivar);
				
				[result appendFormat:@"\t%@\n", [ClassDump variableDefinitionWithName: ivarTypeEncoding name: ivarName]];
				
			}
			
			[result appendString:@"}"];
		}
		
		free(ivars);
	}
	
	[result appendString:@"\n\n"];
	
	unsigned int propertyCount;
	objc_property_t *properties = class_copyPropertyList(class, &propertyCount);
	
	if(properties) {
		for(unsigned int i = 0; i < propertyCount; i++) {
			objc_property_t property = properties[i];
			const char *propertyName = property_getName(property);
			
			unsigned int propertyAttributeCount;
			objc_property_attribute_t *propertyAttributes = property_copyAttributeList(property, &propertyAttributeCount);
			
			BOOL isDynamic = NO;
			NSMutableString *attributesString = [NSMutableString new];
			char *typeEncoding = NULL;
			
			if(propertyAttributes) {
				BOOL firstAttribute = YES;
				for(unsigned int j = 0; j < propertyAttributeCount; j++) {
					objc_property_attribute_t *propertyAttribute = propertyAttributes + j;
					
					NSString *attribute = nil;
					const char *attributeValue = nil;
					
					switch(propertyAttribute->name[0]) {
						case 'V':
							break;
						case 'T':
							typeEncoding = strdup(propertyAttribute->value);
							break;
						case 'R':
							attribute = @"readonly";
							break;
						case 'C':
							attribute = @"copy";
							break;
						case '&':
							attribute = @"retain";
							break;
						case 'N':
							attribute = @"nonatomic";
							break;
						case 'G':
							attribute = @"getter";
							attributeValue = propertyAttribute->value;
							break;
						case 'S':
							attribute = @"setter";
							attributeValue = propertyAttribute->value;
							break;
						case 'D':
							isDynamic = YES;
							break;
						case 'W':
							attribute = @"__weak";
							break;
						case 'P':
							// Garbage collection
							break;
                        case '?':
                            break;
						case 't':
							assert(0);
							break;
						default:
						    NSLog(@"Unknown name: %s, propertyAttributeCount=%d, i=%d, attribute=%@, attributeValue=%s, typeEncoding=%s, propertyName=%s\n", propertyAttribute->name, propertyAttributeCount, i, attribute, attributeValue, typeEncoding, propertyName);
							assert(0);
							break;
					}
					
					if(attribute) {
						if(firstAttribute) {
							[attributesString appendString:@"("];
							
							firstAttribute = NO;
						} else {
							[attributesString appendString:@", "];
						}
						
						[attributesString appendString:attribute];
						
						if(attributeValue) {
							[attributesString appendFormat:@"=%s", attributeValue];
						}
					}
				}
				
				if(!firstAttribute) {
					[attributesString appendFormat:@") "];
				}
				
				free(propertyAttributes);
			}
			
			assert(typeEncoding);
			
			NSString *propertyType = [ClassDump methodArgTypeString: typeEncoding];
			if([propertyType hasSuffix: @"*"]) {
			    [result appendFormat:@"@property %@%@%s;\n", attributesString, propertyType, propertyName];
			} else {
			    [result appendFormat:@"@property %@%@ %s;\n", attributesString, propertyType, propertyName];
			}
			
			free(typeEncoding);
		}
		
		free(properties);
		
		[result appendString:@"\n"];
	}
	
	for(int m = 0; m < 2; m++) {
		unsigned int methodCount;
		Method *methods = class_copyMethodList(m? class: objc_getMetaClass(className), &methodCount);
		
		if(methods) {
			for(unsigned int i = 0; i < methodCount; i++) {
				[result appendString:m? @"- ": @"+ "];
				
				Method method = methods[i];
				
				char *returnTypeEncoding = method_copyReturnType(method);
				NSString *returnType = [ClassDump methodArgTypeString: returnTypeEncoding];
				free(returnTypeEncoding);
				
				[result appendFormat:@"(%@)", returnType];
				
				const char *methodName = sel_getName(method_getName(method));
				NSString *methodString = [NSString stringWithUTF8String:methodName];
				
				NSArray *methodParts = [methodString componentsSeparatedByString:@":"];
				
				[result appendString:methodParts[0]];
				
				unsigned int argCount = method_getNumberOfArguments(method);
				if(argCount == 0) {
					argCount = 2;
				}

				if(argCount - 2 != [methodParts count] - 1) {
				    NSLog(@"argCount - 2 == [methodParts count] - 1: %@", result);
				}
				assert(argCount - 2 == [methodParts count] - 1);
				
				for(unsigned int j = 0; j < argCount - 2; j++) {
					char *argTypeEncoding = method_copyArgumentType(method, j + 2);
					NSString *argType = [ClassDump methodArgTypeString: argTypeEncoding];
					free(argTypeEncoding);
					
					if(j != 0) {
						[result appendFormat:@" %@", methodParts[j]];
					}
					[result appendFormat:@":(%@)arg%d", argType, j];
				}

				if([methodParts count] > 2) {
				    [result appendFormat:@"; // %s\n", methodName];
				} else {
				    [result appendString:@";\n"];
				}
			}
			
			free(methods);
			
			[result appendString:@"\n"];
		}
	}
	
	[result appendString:@"@end"];
	
	return result;
}

BOOL isSystemClass(Class class) {
#if 0
	const char *name = class_getName(class);
	
	const char *cmp_name = name;
	
	while(*cmp_name == '_') {
		cmp_name++;
	}
	
	if(strncmp("NS", cmp_name, 2) == 0 || strncmp("CF", cmp_name, 2) == 0 || strncmp("OS", cmp_name, 2) == 0 || strncmp("DD", cmp_name, 2) == 0 || strncmp("MD", cmp_name, 2) == 0 || strncmp("XN", cmp_name, 2) == 0) {
		return YES;
	}
#endif
	
	void *address = (__bridge void *)class;
	
	if(!address) {
		return NO;
	}
	
	Dl_info info;
	dladdr(address, &info);
	
	const char *libpath = info.dli_fname;
	const char *system_path = "/System/Library/";
	const char *libobjc_path = "/usr/lib/libobjc.A.dylib";
	
	if(strncmp(system_path, libpath, sizeof(system_path) - 1) == 0 || strncmp(libobjc_path, libpath, sizeof(libobjc_path) - 1) == 0) {
		return YES;
	} else {
		return NO;
	}
}

+(NSString *) my_dump_class: (const char *) name {
    Class class = objc_getClass(name);
    if(class) {
        return [ClassDump class_dump_class: class];
    }
    return nil;
}

+(void) search_class: (const char *) keywords {
    int classCount = objc_getClassList(NULL, 0);

	if(classCount < 1) {
	    NSLog(@"Empty objc class.");
		return;
	}
	if(keywords == NULL || strlen(keywords) == 0) {
	    NSLog(@"Search failed: %s", keywords);
	    return;
	}

	__unsafe_unretained Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * classCount);
	objc_getClassList(classes, classCount);
	int count = 0;
	for(int i = 0; i < classCount; i++) {
	    Class class = classes[i];
	    const char *className = class_getName(class);
	    if(strcasestr(className, keywords)) {
	        NSLog(@"Found class: %s => %p", className, class);
	        count++;
	    } else if(matchesSuper(class_getSuperclass(class), keywords)) {
	        NSLog(@"Found super: %s => %p", className, class);
	        count++;
	    }
	}
	free(classes);

    unsigned int protocolCount = 0;
	Protocol **protocols = objc_copyProtocolList(&protocolCount);
	if(protocolCount > 0) {
	    for(int i = 0; i < protocolCount; i++) {
	        const char *protocolName = protocol_getName(protocols[i]);
	        if(strcasestr(protocolName, keywords)) {
                NSLog(@"Found proto: %s => %p", protocolName, protocols[i]);
                count++;
            }
	    }
	    free(protocols);
	}

	NSLog(@"Search class matches count: %d", count);
}

+(NSString *) class_dump_all_classes: (BOOL) includeSystemClasses {
	NSMutableString *result = [NSMutableString new];
	
	int classCount = objc_getClassList(NULL, 0);
	
	if(classCount < 1) {
		return nil;
	}
	
	__unsafe_unretained Class *classes = (__unsafe_unretained Class *)malloc(sizeof(Class) * classCount);
	objc_getClassList(classes, classCount);

	for(int i = 0; i < classCount; i++) {
		if(includeSystemClasses || !isSystemClass(classes[i])) {
			[result appendString:[ClassDump class_dump_class: classes[i]]];
			[result appendString:@"\n\n"];
		}
	}
	
	free(classes);
	
	return result;
}

@end
