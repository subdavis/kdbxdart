import "dart:typed_data";

import "package:test/test.dart";
import "package:cryptoutils/utils.dart";

import "package:kdbxdart/kdbx.dart";

main() {
  test('BLAKE2b', () {
    var blake2b = new Blake2b(new Uint8List(32), 32);
  });
}