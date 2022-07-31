#import <CoreFoundation/CoreFoundation.h>

typedef UInt32 AudioObjectID;
typedef UInt32 AudioObjectPropertyElement;
typedef UInt32 AudioObjectPropertyScope;
typedef UInt32 AudioObjectPropertySelector;

typedef struct AudioObjectPropertyAddress {
    AudioObjectPropertyElement mElement;
    AudioObjectPropertyScope mScope;
    AudioObjectPropertySelector mSelector;
} AudioObjectPropertyAddress;

Boolean AudioObjectHasProperty(AudioObjectID inObjectID, const AudioObjectPropertyAddress *inAddress);
