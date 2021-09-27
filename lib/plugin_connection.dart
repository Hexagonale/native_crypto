import 'dart:typed_data';

import 'package:flutter/services.dart';

class PluginConnection {
  static const MethodChannel _channel = const MethodChannel('crypto');
  static BasicMessageChannel<Uint8List> _dataChannel = BasicMessageChannel('data', BinaryCodec())
    ..setMessageHandler(_onBinaryMessage);

  static Uint8List? _buffer;

  // Commands
  static Future<int?> create({
    required Uint8List key,
    required Uint8List iv,
    required bool forEncryption,
  }) {
    return _channel.invokeMethod<int>('create', {
      'key': key,
      'iv': iv,
      'encryption': forEncryption,
    });
  }

  static Future<Uint8List?> process(int id) async {
    final bool? success = await _channel.invokeMethod<bool>('process', id);

    if (success != true) {
      return null;
    }

    return _buffer;
  }

  static Future<bool> close(int id) async {
    return await _channel.invokeMethod<bool>('close', id) ?? false;
  }

  // Binary
  static Future<void> writeBuffer(Uint8List data) async {
    await _dataChannel.send(data);
  }

  static Future<Uint8List> _onBinaryMessage(Uint8List? message) async {
    _buffer = message;

    return Uint8List(0);
  }

  static Uint8List? get buffer => _buffer;
}

class BinaryCodec extends MessageCodec<Uint8List> {
  @override
  Uint8List? decodeMessage(ByteData? message) {
    return message?.buffer.asUint8List();
  }

  @override
  ByteData? encodeMessage(Uint8List message) {
    return ByteData.sublistView(message);
  }
}
