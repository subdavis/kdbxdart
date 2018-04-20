import "dart:typed_data";

import "package:test/test.dart";
import "package:cryptoutils/utils.dart";

import "package:kdbxdart/kdbx.dart";

void main() {
  test("ChaCha20 without input produces expected keystream", () {
    var key = new Uint8List(32);
    var nonce = new Uint8List(32);
    var chacha20 = new ChaCha20(key, nonce);
    expect(CryptoUtils.bytesToHex(chacha20.getBytes(32)), equals('76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7'));
    expect(CryptoUtils.bytesToHex(chacha20.getBytes(32)), equals('da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586'));
    chacha20.input[12] = 0xffffffff; // input counter overflow uint32
    expect(CryptoUtils.bytesToHex(chacha20.getBytes(16)), equals('ace4cd09e294d1912d4ad205d06f95d9'));
  });
}