#include <CoreFoundation/CoreFoundation.h>

/*!
        @typedef        CMTimeValue
        @abstract       Numerator of rational CMTime.
*/
typedef int64_t CMTimeValue;

/*!
        @typedef        CMTimeScale
        @abstract       Denominator of rational CMTime.
        @discussion     Timescales must be positive.
                                Note: kCMTimeMaxTimescale is NOT a good choice of timescale for movie files.
                                (Recommended timescales for movie files range from 600 to 90000.)
*/
typedef int32_t CMTimeScale;

/*!
        @enum           CMTimeFlags
        @abstract       Flag bits for a CMTime.
        @constant       kCMTimeFlags_Valid Must be set, or the CMTime is considered invalid.
                                                                        Allows simple clearing (eg. with calloc or memset) for initialization
                                                                        of arrays of CMTime structs to "invalid". This flag must be set, even
                                                                        if other flags are set as well.
        @constant       kCMTimeFlags_HasBeenRounded Set whenever a CMTime value is rounded, or is derived from another rounded CMTime.
        @constant       kCMTimeFlags_PositiveInfinity Set if the CMTime is +inf.        "Implied value" flag (other struct fields are ignored).
        @constant       kCMTimeFlags_NegativeInfinity Set if the CMTime is -inf.        "Implied value" flag (other struct fields are ignored).
        @constant       kCMTimeFlags_Indefinite Set if the CMTime is indefinite/unknown. Example of usage: duration of a live broadcast.
                                                                                 "Implied value" flag (other struct fields are ignored).
*/
typedef CF_OPTIONS( uint32_t, CMTimeFlags ) {
        kCMTimeFlags_Valid = 1UL<<0,
        kCMTimeFlags_HasBeenRounded = 1UL<<1,
        kCMTimeFlags_PositiveInfinity = 1UL<<2,
        kCMTimeFlags_NegativeInfinity = 1UL<<3,
        kCMTimeFlags_Indefinite = 1UL<<4,
        kCMTimeFlags_ImpliedValueFlagsMask = kCMTimeFlags_PositiveInfinity | kCMTimeFlags_NegativeInfinity | kCMTimeFlags_Indefinite
};

/*!
        @typedef        CMTimeEpoch
        @abstract       Epoch (eg, loop number) to which a CMTime refers.
*/
typedef int64_t CMTimeEpoch;

typedef struct {
        CMTimeValue     value;          /*!< The value of the CMTime. value/timescale = seconds */
        CMTimeScale     timescale;      /*!< The timescale of the CMTime. value/timescale = seconds. */
        CMTimeFlags     flags;          /*!< The flags, eg. kCMTimeFlags_Valid, kCMTimeFlags_PositiveInfinity, etc. */
        CMTimeEpoch     epoch;          /*!< Differentiates between equal timestamps that are actually different because
                                                                of looping, multi-item sequencing, etc.
                                                                Will be used during comparison: greater epochs happen after lesser ones.
                                                                Additions/subtraction is only possible within a single epoch,
                                                                however, since epoch length may be unknown/variable */
} CMTime;
