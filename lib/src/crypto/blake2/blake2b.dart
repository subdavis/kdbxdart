part of 'blake2';

// FROM WIKIPEDIA:
// Algorithm BLAKE2b
//    Input:
//       M                               Message to be hashed
//       cbMessageLen: Number, (0..2128)  Length of the message in bytes
//       Key                             Optional 0..64 byte key
//       cbKeyLen: Number, (0..64)       Length of optional key in bytes
//       cbHashLen: Number, (1..64)      Desired hash length in bytes
//    Output:
//       Hash                            Hash of cbHashLen bytes

//    Initialize State vector h with IV
//    h0..7 ← IV0..7

//    Mix key size (cbKeyLen) and desired hash length (cbHashLen) into h0
//    h0 ← h0 xor 0x0101kknn
//          where kk is Key Length (in bytes)
//                nn is Desired Hash Length (in bytes)

//    Each time we Compress we record how many bytes have been compressed
//    cBytesCompressed ← 0
//    cBytesRemaining  ← cbMessageLen

//    If there was a key supplied (i.e. cbKeyLen > 0) 
//    then pad with trailing zeros to make it 128-bytes (i.e. 16 words) 
//    and prepend it to the message M
//    if (cbKeyLen > 0) then
//       M ← Pad(Key, 128) || M
//       cBytesRemaining ← cBytesRemaining + 128
//    end if

//    Compress whole 128-byte chunks of the message, except the last chunk
//    while (cBytesRemaining > 128) do
//       chunk ← get next 128 bytes of message M
//       cBytesCompressed ← cBytesCompressed + 128  increase count of bytes that have been compressed
//       cBytesRemaining  ← cBytesRemaining  - 128  decrease count of bytes in M remaining to be processed

//       h ← Compress(h, chunk, cBytesCompressed, false)  false ⇒ this is not the last chunk
//    end while

//    Compress the final bytes from M
//    chunk ← get next 128 bytes of message M  We will get cBytesRemaining bytes (i.e. 0..128 bytes)
//    cBytesCompressed ← cBytesCompressed+cBytesRemaining  The actual number of bytes leftover in M
//    chunk ← Pad(chunk, 128)  If M was empty, then we will still compress a final chunk of zeros

//    h ← Compress(h, chunk, cBytesCompressed, true)  true ⇒ this is the last chunk

//    Result ← first cbHashLen bytes of little endian state vector h
// End Algorithm BLAKE2b
class Blake2b {
  Uint8List _message;
  int _messageLength;
  Uint8List _key;
  int _keyLength;
  int _digestLength;

  // Hash state.
  Uint8List _h; // chain
  Uint8List _t; // counter
  Uint8List _f; // finalization flags
  int cBytesCompressed;
  int cBytesRemaining;

  int get digetsLength => _digestLength;
  int get keyLength => _keyLength;

  _initialize(){
    // Initialize State Vector H with IV
    _h.setRange(0, 0+8, _IV);
    // Mix key size (cbKeyLen) and desired hash length (cbHashLen) into h0
    // h0 ← h0 xor 0x0101kknn
    //    where kk is Key Length (in bytes)
    //          nn is Desired Hash Length (in bytes)
    _h[0] = 0x0101 << 16 | _keyLength << 8 | _digestLength;
    // Each time we Compress we record how many bytes have been compressed
    cBytesRemaining = 0;
    cBytesRemaining = _messageLength;
    // If there was a key supplied (i.e. cbKeyLen > 0) 
    // then pad with trailing zeros to make it 128-bytes (i.e. 16 words) 
    // and prepend it to the message M
  }

  Blake2b(this._message, this._digestLength, [Uint8List key]) 
    : _messageLength = _message.length,
      _key = key,
      _keyLength = key != null ? key.length : 0 {}
}