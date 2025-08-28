/**
 * salman 40 - Enterprise Cryptographic SDK for Dart/Flutter
 * Generated: 2025-08-28T10:26:18.964Z
 */

import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:pointycastle/export.dart';

class AveroxCrypto {
  final Uint8List _masterKey;
  
  AveroxCrypto(this._masterKey) {
    if (_masterKey.length < 32) {
      throw ArgumentError('Master key must be at least 32 bytes');
    }
  }
  
  EncryptedData encrypt(String plaintext, {Uint8List? aad}) {
    final key = _deriveKey();
    final iv = _generateRandomBytes(12);
    
    final cipher = GCMBlockCipher(AESEngine());
    final params = AEADParameters(KeyParameter(key), 128, iv, aad);
    cipher.init(true, params);
    
    final plaintextBytes = utf8.encode(plaintext);
    final ciphertext = Uint8List(plaintextBytes.length + 16);
    final len = cipher.processBytes(plaintextBytes, 0, plaintextBytes.length, ciphertext, 0);
    cipher.doFinal(ciphertext, len);
    
    return EncryptedData(
      iv: base64.encode(iv),
      ciphertext: base64.encode(ciphertext.sublist(0, plaintextBytes.length)),
      tag: base64.encode(ciphertext.sublist(plaintextBytes.length))
    );
  }
  
  Uint8List _deriveKey() {
    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));
    pbkdf2.init(Pbkdf2Parameters(utf8.encode('averox-salt'), 100000, 32));
    return pbkdf2.process(_masterKey);
  }
  
  Uint8List _generateRandomBytes(int length) {
    final random = SecureRandom('Fortuna');
    final seed = Uint8List(32);
    for (int i = 0; i < 32; i++) {
      seed[i] = (DateTime.now().millisecondsSinceEpoch + i) & 0xFF;
    }
    random.seed(KeyParameter(seed));
    return random.nextBytes(length);
  }
}

class EncryptedData {
  final String iv;
  final String ciphertext;
  final String tag;
  
  EncryptedData({required this.iv, required this.ciphertext, required this.tag});
}