import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import '../native_crypto.dart';
import '../plugin_connection.dart';

// TODO: Move generic methods to abstract cipher class and extend it here.

/// Class used to process data using AES-256 cipher in CBC mode.
///
/// It uses native cipher methods for current platform to maximally use the CPU performance.
/// Currently supports only Windows.
///
/// It needs to be initialized using `init` method before processing data.
///
/// Class is written so it behaves like a stream, so you can chain it with other streams for performance.
class AesCbcCipher with Sink<Uint8List> {
  /// Constructor used only to check platform.
  AesCbcCipher() : assert(Platform.isWindows);

  /// Size of cipher block in bytes.
  /// For AES it's always 16.
  static const int blockSize = 16;

  /// Stream controller for processed data.
  ///
  /// Whenever data passed by any of `add` methods can be processed,
  /// it emits plain / cipher text, depending on the `forEncryption` parameter
  /// passed for initialization.
  final StreamController<Uint8List> _controller = StreamController<Uint8List>.broadcast();

  /// Id of native cipher instance.
  ///
  /// It's null if cipher is not yet initialized.
  int? _id;

  /// Buffer for data that does not fit to block size.
  ///
  /// Whenever length of data passed by any of `add` methods is not multiply of block size,
  /// overflowed part is stored here. It's processed when next data is passed or it's padded
  /// and processed when `close` is called.
  Uint8List buffer = Uint8List(0);

  /// Padding type that's used when `close` is called.
  PaddingType paddingType = PaddingType.PKCS;

  /// Inits native instance of cipher.
  ///
  /// This method can be called only once.
  /// It returns `true` if initialization was successful.
  ///
  /// [key] is used to derive cipher key.
  /// It can be of any length.
  /// Real key used for processing data is derived using sha256(key).
  ///
  /// [forEncryption] specifies if current cipher instance is used to encrypt or decrypt data.
  /// It should be `true` if cipher is used to encrypt data.
  ///
  /// [initializationVector] is used to initialize CBC mode.
  /// It's length should be equal to [blockSize], although if it's larger it is truncated.
  /// If it's null it is generated randomly.
  ///
  /// [paddingType] refer to `this.paddingType`.
  /// Defaults to `PaddingType.PKCS` padding.
  ///
  /// This method can throw an `CipherException` if cipher is already initialized.
  Future<bool> init({
    required Uint8List key,
    required bool forEncryption,
    Uint8List? initializationVector,
    PaddingType? paddingType,
  }) async {
    if (ready) {
      throw CipherError('Already initialized.');
    }

    // Default
    initializationVector ??= generateRandomBytes(blockSize);
    this.paddingType = paddingType ?? this.paddingType;

    _id = await PluginConnection.create(
      key: key,
      iv: initializationVector,
      forEncryption: forEncryption,
    );

    return _id != null;
  }

  /// Method for adding stream of data to be processed.
  ///
  /// It returns Future that completes when [stream] is finished.
  ///
  /// Cipher has to be initialized before calling this method.
  Future<void> addStream(Stream<Uint8List> stream) async {
    await for (Uint8List data in stream) {
      add(data);
    }
  }

  /// Adds [data] to be processed by the cipher.
  ///
  /// It concatenates internal buffer and [data] aligns it to [blockSize] and then processes it.
  /// Data that overflows is saved to internal buffer to be processed with next call to this method or `close`.
  ///
  /// If concatenated internal buffer and [data] length is smaller than the [blockSize],
  /// the data is saved to the internal buffer and no event is emitted by the [stream].
  ///
  /// [data] must not be empty.
  ///
  /// Returns `true` if data is processed and event emitted by the [stream].
  /// Otherwise returns `false`.
  ///
  /// Cipher has to be initialized before calling this method.
  @override
  Future<bool> add(Uint8List data) async {
    if (!ready) {
      throw CipherError('Cipher is not ready');
    }

    if (data.isEmpty) {
      throw CipherError('Data is empty');
    }

    if (buffer.isNotEmpty) {
      data = Uint8List.fromList([...buffer, ...data]);
      buffer = Uint8List(0);
    }

    final int overflow = data.length % blockSize;
    if (overflow != 0) {
      buffer = data.sublist(data.length - overflow);
      data = data.sublist(0, data.length - overflow);
    }

    // Data is smaller than block size. Save it to the buffer.
    if (data.length == 0) {
      return false;
    }

    final Uint8List processed = await _processData(data);
    _controller.add(processed);

    return true;
  }

  /// Closes cipher and disposes underlying native cipher instance.
  ///
  /// This method can cause [stream] to emit last block of data.
  ///
  /// It must be called to prevent memory leaks.
  @override
  Future<void> close() async {
    await _finish();
    _controller.close();

    await PluginConnection.close(_id!);

    return;
  }

  /// Flushes data that's left in the [buffer].
  ///
  /// Pads data that's left in the [buffer], processes it and adds it to [_controller].
  Future<void> _finish() async {
    // TODO: If buffer is empty attach whole padding block.
    final Uint8List data = BytesPadding.add(
      data: buffer,
      length: blockSize,
      paddingType: paddingType,
    );

    final Uint8List processed = await _processData(data);
    _controller.add(processed);
  }

  /// Processes given [data].
  ///
  /// Writes native buffer with [data] and then calls native process method.
  /// [data] needs to be aligned to blockSize.
  /// Cipher needs to be initialized before calling this method.
  ///
  /// Returns processed data.
  Future<Uint8List> _processData(Uint8List data) async {
    await PluginConnection.writeBuffer(data);

    final Uint8List? processed = (await PluginConnection.process(_id!)) ?? Uint8List(0);

    if (processed == null) {
      throw CipherError('Cannot process data');
    }

    return processed;
  }

  /// Indicates if cipher instance has been initialized and is ready to use.
  bool get ready => _id != null;

  /// Stream that emits processed data.
  ///
  /// Whenever data passed by any of `add` methods can be processed.
  /// This stream emits block(s) of processed data.
  Stream<Uint8List> get stream => _controller.stream;
}

// TODO: Move it somewhere when it's truly generic and can be used by any other cipher.
/// Generic class for an error connected to [AesCbcCipher].
class CipherError extends Error {
  CipherError(this.message);

  final String message;

  @override
  String toString() {
    return 'CipherError: $message';
  }
}
