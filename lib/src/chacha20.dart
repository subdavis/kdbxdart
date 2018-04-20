import 'dart:typed_data';

/// An implementation of ChaCha20 KDF
class ChaCha20 {
  static const List<int> sigmaWords = const [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
  
  final Uint8List key, nonce;
  Uint8List block = new Uint8List(64);
  Uint32List x = new Uint32List(16);
  Uint32List input = new Uint32List(16);
  int blockUsed = 64;

  /// Convert 32 bits of a Uint8List [x] of length >= [i]+4 to a single Uint32 value 
  /// return is little endian
  static int _u8to32le(Uint8List x, int i) {
    return x[i] | (x[i + 1] << 8) | (x[i + 2] << 16) | (x[i + 3] << 24);
  }

  /// Convert [u32] to four indices i...i+3 in [x]
  /// result is little endian
  static void _u32to8le(Uint8List x, int i, u32) {
    x[i] = u32;
    u32 >>= 8;
    x[i+1] = u32;
    u32 >>= 8;
    x[i+2] = u32;
    u32 >>= 8;
    x[i+3] = u32;
  }

  static int _rotate(int v, c)=> (v << c) | (v >> (32 - c));

  static void _quarterRound(Uint32List x, int a, b, c, d) {
    x[a] += x[b];
    x[d] = _rotate(x[d] ^ x[a], 16);
    x[c] += x[d];
    x[b] = _rotate(x[b] ^ x[c], 12);
    x[a] += x[b];
    x[d] = _rotate(x[d] ^ x[a], 8);
    x[c] += x[d];
    x[b] = _rotate(x[b] ^ x[c], 7);
  }

  /// Derive [numberOfBytes] of keystream
  Uint8List getBytes (int numberOfBytes) {
    var out = new Uint8List(numberOfBytes);
    for (var i = 0; i < numberOfBytes; i++) {
        if (blockUsed == 64) {
            this._generateBlock();
            this.blockUsed = 0;
        }
        out[i] = this.block[this.blockUsed];
        this.blockUsed++;
    }
    return out;
  }

  _generateBlock() {
    var input = this.input;
    var x = this.x;
    var block = this.block;
    var i;

    x.setAll(0, input);
    for (i = 20; i > 0; i -= 2) {
        _quarterRound(x, 0, 4, 8, 12);
        _quarterRound(x, 1, 5, 9, 13);
        _quarterRound(x, 2, 6, 10, 14);
        _quarterRound(x, 3, 7, 11, 15);
        _quarterRound(x, 0, 5, 10, 15);
        _quarterRound(x, 1, 6, 11, 12);
        _quarterRound(x, 2, 7, 8, 13);
        _quarterRound(x, 3, 4, 9, 14);
    }
    for (i = 16; i-- > 0;) {
        x[i] += input[i];
    }
    for (i = 16; i-- > 0;) {
        _u32to8le(block, 4 * i, x[i]);
    }

    input[12] += 1;
    if (input[12] == 0) {
        input[13] += 1;
    }
}

  /// Given [key] and [nonce] create a ChaCha20 stream cipher generator
  ChaCha20(this.key, this.nonce) {
    // TODO: assert lengths in D2
    input[0] = sigmaWords[0];
    input[1] = sigmaWords[1];
    input[2] = sigmaWords[2];
    input[3] = sigmaWords[3];
    input[4] = _u8to32le(key, 0);
    input[5] = _u8to32le(key, 4);
    input[6] = _u8to32le(key, 8);
    input[7] = _u8to32le(key, 12);
    input[8] = _u8to32le(key, 16);
    input[9] = _u8to32le(key, 20);
    input[10] = _u8to32le(key, 24);
    input[11] = _u8to32le(key, 28);
    input[12] = 0; // counter

    if (nonce.length == 12) {
        input[13] = _u8to32le(nonce, 0);
        input[14] = _u8to32le(nonce, 4);
        input[15] = _u8to32le(nonce, 8);
    } else {
        input[13] = 0;
        input[14] = _u8to32le(nonce, 0);
        input[15] = _u8to32le(nonce, 4);
    }
  }
}