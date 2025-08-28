/**
 * salman 40 - Enterprise Cryptographic SDK for Objective-C
 * Generated: 2025-08-28T10:26:18.965Z
 */

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>

@interface EncryptedData : NSObject
@property (nonatomic, strong) NSString *iv;
@property (nonatomic, strong) NSString *ciphertext;
@property (nonatomic, strong) NSString *tag;
@end

@interface AveroxCrypto : NSObject
- (instancetype)initWithMasterKey:(NSData *)masterKey error:(NSError **)error;
- (EncryptedData *)encrypt:(NSString *)plaintext aad:(NSData *)aad error:(NSError **)error;
- (NSString *)decrypt:(EncryptedData *)encrypted aad:(NSData *)aad error:(NSError **)error;
@end