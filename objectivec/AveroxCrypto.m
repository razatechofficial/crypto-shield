#import "AveroxCrypto.h"
#import <Security/Security.h>

@implementation EncryptedData
@end

@implementation AveroxCrypto {
    NSData *_masterKey;
}

- (instancetype)initWithMasterKey:(NSData *)masterKey error:(NSError **)error {
    self = [super init];
    if (self) {
        if (masterKey.length < 32) {
            if (error) {
                *error = [NSError errorWithDomain:@"AveroxCrypto" code:1 userInfo:@{NSLocalizedDescriptionKey: @"Master key must be at least 32 bytes"}];
            }
            return nil;
        }
        _masterKey = [masterKey copy];
    }
    return self;
}

- (EncryptedData *)encrypt:(NSString *)plaintext aad:(NSData *)aad error:(NSError **)error {
    NSData *key = [self deriveKey];
    NSMutableData *iv = [NSMutableData dataWithLength:12];
    SecRandomCopyBytes(kSecRandomDefault, 12, iv.mutableBytes);
    
    NSData *plaintextData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *ciphertext = [NSMutableData dataWithLength:plaintextData.length];
    NSMutableData *tag = [NSMutableData dataWithLength:16];
    
    CCCryptorStatus status = CCCryptorGCM(kCCEncrypt, kCCAlgorithmAES,
                                         key.bytes, key.length,
                                         iv.bytes, iv.length,
                                         aad.bytes, aad.length,
                                         plaintextData.bytes, plaintextData.length,
                                         ciphertext.mutableBytes,
                                         tag.mutableBytes, &tag.length);
    
    if (status != kCCSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:@"AveroxCrypto" code:2 userInfo:@{NSLocalizedDescriptionKey: @"Encryption failed"}];
        }
        return nil;
    }
    
    EncryptedData *result = [[EncryptedData alloc] init];
    result.iv = [iv base64EncodedStringWithOptions:0];
    result.ciphertext = [ciphertext base64EncodedStringWithOptions:0];
    result.tag = [tag base64EncodedStringWithOptions:0];
    
    return result;
}

- (NSData *)deriveKey {
    NSData *salt = [@"averox-salt" dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *derivedKey = [NSMutableData dataWithLength:32];
    
    CCKeyDerivationPBKDF(kCCPBKDF2, _masterKey.bytes, _masterKey.length,
                        salt.bytes, salt.length,
                        kCCPRFHmacAlgSHA256, 100000,
                        derivedKey.mutableBytes, derivedKey.length);
    
    return derivedKey;
}

@end