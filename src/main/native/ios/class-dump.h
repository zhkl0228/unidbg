//
//  class-dump.h
//  runtime_class-dump
//
//  Created by Asger Hautop Drewsen on 5/6/14.
//  Copyright (c) 2014 Tyilo. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ClassDump : NSObject

+(NSString *) basicTypeFromEncoding: (const char *) encoding;
+(NSArray *) typeStringFromEncoding: (const char *) typeEncoding end: (NSUInteger *) end;
+(NSString *) variableDefinitionWithName: (const char *) typeEncoding name: (const char *) name;
+(NSString *) methodArgTypeString: (const char *) typeEncoding;
+(NSString *) my_dump_class: (const char *) name;
+(NSString *) class_dump_class: (Class) clazz;
+(NSString *) class_dump_all_classes: (BOOL) includeSystemClasses;

@end
