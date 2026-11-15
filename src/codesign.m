#include <Foundation/Foundation.h>
#include <Security/Security.h>
#include <TargetConditionals.h>

#ifdef __cplusplus
extern "C" {
#endif

#if TARGET_OS_OSX
#include <Security/SecCode.h>
#include <Security/SecStaticCode.h>
#else

// CSCommon.h
typedef struct CF_BRIDGED_TYPE(id) __SecCode const *SecStaticCodeRef; // code on disk

typedef CF_OPTIONS(uint32_t, SecCSFlags) {
    kSecCSDefaultFlags = 0, // no particular flags (default behavior)

    kSecCSConsiderExpiration = 1U << 31, // consider expired certificates invalid
    kSecCSEnforceRevocationChecks = 1 << 30, // force revocation checks regardless of preference settings
    kSecCSNoNetworkAccess = 1 << 29, // do not use the network, cancels "kSecCSEnforceRevocationChecks"
    kSecCSReportProgress = 1 << 28, // make progress report call-backs when configured
    kSecCSCheckTrustedAnchors = 1 << 27, // build certificate chain to system trust anchors, not to any self-signed certificate
    kSecCSQuickCheck = 1 << 26, // (internal)
    kSecCSApplyEmbeddedPolicy = 1 << 25, // Apply Embedded (iPhone) policy regardless of the platform we're running on
};

enum {
    kSecCodeSignatureHost = 0x0001, // may host guest code
    kSecCodeSignatureAdhoc = 0x0002, // must be used without signer
    kSecCodeSignatureForceHard = 0x0100, // always set HARD mode on launch
    kSecCodeSignatureForceKill = 0x0200, // always set KILL mode on launch
    kSecCodeSignatureForceExpiration = 0x0400, // force certificat expiration checks
};

// SecStaticCode.h
OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes, SecStaticCodeRef *__nonnull CF_RETURNS_RETAINED staticCode);

// SecCode.h
CF_ENUM(uint32_t) {
    kSecCSInternalInformation = 1 << 0,
    kSecCSSigningInformation = 1 << 1,
    kSecCSRequirementInformation = 1 << 2,
    kSecCSDynamicInformation = 1 << 3,
    kSecCSContentInformation = 1 << 4,
    kSecCSSkipResourceDirectory = 1 << 5,
    kSecCSCalculateCMSDigest = 1 << 6,
};

OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef *__nonnull CF_RETURNS_RETAINED information);

extern const CFStringRef kSecCodeInfoEntitlements; // generic
extern const CFStringRef kSecCodeInfoIdentifier; // generic
extern const CFStringRef kSecCodeInfoRequirementData; // Requirement

#endif

typedef CF_OPTIONS(uint32_t, SecPreserveFlags) {
    kSecCSPreserveIdentifier = 1 << 0,
    kSecCSPreserveRequirements = 1 << 1,
    kSecCSPreserveEntitlements = 1 << 2,
    kSecCSPreserveResourceRules = 1 << 3,
    kSecCSPreserveFlags = 1 << 4,
    kSecCSPreserveTeamIdentifier = 1 << 5,
    kSecCSPreserveDigestAlgorithm = 1 << 6,
    kSecCSPreservePreEncryptHashes = 1 << 7,
    kSecCSPreserveRuntime = 1 << 8,
};

// SecCodeSigner.h
#ifdef BRIDGED_SECCODESIGNER
typedef struct CF_BRIDGED_TYPE(id) __SecCodeSigner *SecCodeSignerRef SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
#else
typedef struct __SecCodeSigner *SecCodeSignerRef SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
#endif

extern const CFStringRef kSecCodeSignerEntitlements SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
extern const CFStringRef kSecCodeSignerFlags SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
extern const CFStringRef kSecCodeSignerIdentifier SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
extern const CFStringRef kSecCodeSignerIdentity SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
extern const CFStringRef kSecCodeSignerPreserveMetadata SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
extern const CFStringRef kSecCodeSignerRequirements SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
extern const CFStringRef kSecCodeSignerResourceRules SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));

#ifdef BRIDGED_SECCODESIGNER
OSStatus SecCodeSignerCreate(CFDictionaryRef parameters, SecCSFlags flags, SecCodeSignerRef *__nonnull CF_RETURNS_RETAINED signer) SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
#else
OSStatus SecCodeSignerCreate(CFDictionaryRef parameters, SecCSFlags flags, SecCodeSignerRef *signer) SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));
#endif

OSStatus SecCodeSignerAddSignatureWithErrors(SecCodeSignerRef signer, SecStaticCodeRef code, SecCSFlags flags, CFErrorRef *errors) SPI_AVAILABLE(macos(10.5), ios(15.0), macCatalyst(13.0));

// SecCodePriv.h
extern const CFStringRef kSecCodeInfoResourceDirectory; // Internal

#ifdef __cplusplus
}
#endif

int verbose = 0;

int codesign_sign_adhoc(const char *path, NSString *identifier, bool preserveMetadata, NSDictionary *customEntitlements) {
    NSString *filePath = [NSString stringWithUTF8String:path];
    OSStatus status = 0;
    int retval = 200;

    // the special value "-" (dash) indicates ad-hoc signing
    SecIdentityRef identity = (SecIdentityRef)kCFNull;
    NSMutableDictionary *parameters = [[NSMutableDictionary alloc] init];
    parameters[(__bridge NSString *)kSecCodeSignerIdentity] = (__bridge id)identity;
    uint64_t preserveMetadataFlags = 0;
    if (preserveMetadata) {
        preserveMetadataFlags = (kSecCSPreserveIdentifier | kSecCSPreserveRequirements | kSecCSPreserveEntitlements | kSecCSPreserveResourceRules);
        if (!customEntitlements) {
            preserveMetadataFlags |= kSecCSPreserveEntitlements;
        }
        parameters[(__bridge NSString *)kSecCodeSignerPreserveMetadata] = @(preserveMetadataFlags);
    }

    if (identifier) {
        parameters[(__bridge NSString *)kSecCodeSignerIdentifier] = identifier;
    }

    if (customEntitlements) {
        NSError *error;
        NSData *xmlData = [NSPropertyListSerialization dataWithPropertyList:customEntitlements format:NSPropertyListXMLFormat_v1_0 options:0 error:&error];
        if (!xmlData) {
            NSLog(@"Failed to encode entitlements: %@", error);
            return -1;
        } else {
            // Super easy to use API, definitely not busted...
            // Did I forget to mention it just segfaults if you don't add this prefix?
            uint32_t entitlementsData[xmlData.length + 8];
            entitlementsData[0] = OSSwapHostToBigInt32(0xFADE7171);
            entitlementsData[1] = OSSwapHostToBigInt32(xmlData.length + 8);
            [xmlData getBytes:&entitlementsData[2] length:xmlData.length];
            parameters[(__bridge NSString *)kSecCodeSignerEntitlements] = [NSData dataWithBytes:entitlementsData length:xmlData.length + 8];
        }
    }

#if 0
    parameters[(__bridge NSString*)kSecCodeSignerFlags] = @(kSecCodeSignatureAdhoc);
#endif

    SecCodeSignerRef signerRef;
    status = SecCodeSignerCreate((__bridge CFDictionaryRef)parameters, kSecCSDefaultFlags, &signerRef);
    if (status == 0) {
        SecStaticCodeRef code;
        status = SecStaticCodeCreateWithPathAndAttributes((__bridge CFURLRef)[NSURL fileURLWithPath:filePath], kSecCSDefaultFlags, (__bridge CFDictionaryRef) @{}, &code);
        if (status == 0) {
            CFErrorRef errors;
            status = SecCodeSignerAddSignatureWithErrors(signerRef, code, kSecCSDefaultFlags, &errors);
            if (status == 0) {
                CFDictionaryRef newSigningInformation;
                // Difference from codesign: added kSecCSSigningInformation, kSecCSRequirementInformation, kSecCSInternalInformation
                status = SecCodeCopySigningInformation(code, kSecCSDefaultFlags | kSecCSSigningInformation | kSecCSRequirementInformation | kSecCSInternalInformation, &newSigningInformation);
                if (status == 0) {
                    if (verbose) printf("SecCodeCopySigningInformation succeeded: %s\n", ((__bridge NSDictionary *)newSigningInformation).description.UTF8String);
                    retval = 0;
                    CFRelease(newSigningInformation);
                } else {
                    if (verbose) printf("SecCodeCopySigningInformation failed: %s (%d)\n", ((__bridge NSString *)SecCopyErrorMessageString(status, NULL)).UTF8String, status);
                    retval = 203;
                }
            } else {
                if (verbose) printf("Error while signing: %s\n", ((__bridge NSError *)errors).description.UTF8String);
            }
            CFRelease(code);
        } else {
            if (verbose) printf("SecCodeCopySigningInformation failed: %s (%d)\n", ((__bridge NSString *)SecCopyErrorMessageString(status, NULL)).UTF8String, status);
            retval = 202;
        }
        CFRelease(signerRef);
    } else {
        if (verbose) printf("SecStaticCodeCreateWithPathAndAttributes failed: %s (%d)\n", ((__bridge NSString *)SecCopyErrorMessageString(status, NULL)).UTF8String, status);
        retval = 201;
    }

    return retval;
}

int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
            for (int j = i; j < argc - 1; ++j) argv[j] = argv[j + 1];
            --argc;
            break;
        }
    }

    if (argc < 2) {
        printf("Usage: %s [-v] [-e <plist>] [-i <identifier>] <input_file>\n", getprogname());
        return -1;
    }

    char *input = argv[argc - 1];

    NSDictionary *customEntitlements = nil;
    NSString *identifier = nil;
    for (int i = 1; i < argc - 1; ++i) {
        if (!strcmp(argv[i], "-e") && i + 1 < argc - 1) {
            NSString *entitlementsPath = [NSString stringWithUTF8String:argv[++i]];
            customEntitlements = [NSDictionary dictionaryWithContentsOfFile:entitlementsPath];
        } else if (!strcmp(argv[i], "-i") && i + 1 < argc - 1) {
            identifier = [NSString stringWithUTF8String:argv[++i]];
        }
    }

    char *machoPath = input;

    int r = codesign_sign_adhoc(machoPath, identifier, true, customEntitlements);
    if (r != 0) {
        printf("Failed adhoc signing (%d) Continuing anyways...\n", r);
    } else {
        if (verbose) printf("AdHoc signed file!\n");
    }

    return 0;
}
