import 'dart:typed_data';

import 'generate_random_bytes.dart';

enum PaddingType {
  TBC,
  PKCS,
  ISO7816,
  ISO10126,
  ANSI,
}

class BytesPadding {
  static int _getPaddingLength({
    required int dataLength,
    required int requiredLength,
  }) {
    final int overflow = dataLength % requiredLength;

    return requiredLength - overflow;
  }

  /// Adds specified padding.
  ///
  /// Refer to documentation of specific padding passed in [paddingType].
  static Uint8List add({
    required Uint8List data,
    required int length,
    required PaddingType paddingType,
  }) {
    switch (paddingType) {
      case PaddingType.TBC:
        return addTBC(
          data: data,
          length: length,
        );

      case PaddingType.PKCS:
        return addPKCS(
          data: data,
          length: length,
        );

      case PaddingType.ISO7816:
        return addISO7816(
          data: data,
          length: length,
        );

      case PaddingType.ISO10126:
        return addISO10126(
          data: data,
          length: length,
        );

      case PaddingType.ANSI:
        return addANSI(
          data: data,
          length: length,
        );
    }
  }

  /// Removes specified padding.
  ///
  /// Refer to documentation of specific padding passed in [paddingType].
  static Uint8List remove({
    required Uint8List data,
    required PaddingType paddingType,
  }) {
    switch (paddingType) {
      case PaddingType.TBC:
        return removeTBC(data);

      case PaddingType.PKCS:
        return removePKCS(data);

      case PaddingType.ISO7816:
        return removeISO7816(data);

      case PaddingType.ISO10126:
        return removeISO10126(data);

      case PaddingType.ANSI:
        return removeANSI(data);
    }
  }

  /// Adds TBC padding.
  ///
  /// Copies content to new array.
  static Uint8List addTBC({
    required Uint8List data,
    required int length,
  }) {
    final int paddingLength = _getPaddingLength(
      dataLength: data.length,
      requiredLength: length,
    );

    // Get trailing bit by negation of last bit.
    final int trailingByte = (data.last & 1) == 1 ? 0 : 255;

    final List<int> padding = List<int>.filled(
      paddingLength,
      trailingByte,
    );

    return Uint8List.fromList([
      ...data,
      ...padding,
    ]);
  }

  /// Removes TBC padding.
  ///
  // Copies content to new array.
  static Uint8List removeTBC(Uint8List data) {
    final int trailingByte = data.last;

    int contentLength = data.length - 2;
    while (contentLength > 0) {
      if (data[contentLength] != trailingByte) {
        break;
      }

      contentLength--;
    }

    return data.sublist(0, contentLength + 1);
  }

  /// Adds PKCS padding.
  ///
  /// [length] must be smaller than 255 due to limitations of PKCS padding.
  /// Copies content to new array.
  static Uint8List addPKCS({
    required Uint8List data,
    required int length,
  }) {
    // PKCS can be only used with block size smaller than 255.
    assert(length <= 255);

    final int paddingLength = _getPaddingLength(
      dataLength: data.length,
      requiredLength: length,
    );

    final List<int> padding = List<int>.filled(
      paddingLength,
      paddingLength,
    );

    return Uint8List.fromList([
      ...data,
      ...padding,
    ]);
  }

  /// Removes PKCS padding.
  ///
  // Copies content to new array.
  static Uint8List removePKCS(Uint8List data) {
    final int paddingLength = data.last;

    return data.sublist(0, data.length - paddingLength);
  }

  /// Adds ISO 7816-4 padding.
  ///
  /// Copies content to new array.
  static Uint8List addISO7816({
    required Uint8List data,
    required int length,
  }) {
    final int paddingLength = _getPaddingLength(
      dataLength: data.length,
      requiredLength: length,
    );

    final List<int> padding = List<int>.filled(
      paddingLength - 1,
      0,
    );

    return Uint8List.fromList([
      ...data,
      0x8,
      ...padding,
    ]);
  }

  /// Removes ISO 7816-4 padding.
  ///
  // Copies content to new array.
  static Uint8List removeISO7816(Uint8List data) {
    int contentLength = data.length - 1;
    while (contentLength > 0) {
      if (data[contentLength] != 0) {
        break;
      }

      contentLength--;
    }

    return data.sublist(0, contentLength);
  }

  /// Adds ISO 10126-2 padding.
  ///
  /// [length] must be smaller than 255 due to limitations of ISO 10126-2 padding.
  /// `Warning!` This padding adds random bytes. Output is not predictable.
  /// Copies content to new array.
  static Uint8List addISO10126({
    required Uint8List data,
    required int length,
  }) {
    // ISO 10126-2 can be only used with block size smaller than 255.
    assert(length <= 255);

    final int paddingLength = _getPaddingLength(
      dataLength: data.length,
      requiredLength: length,
    );

    final List<int> padding = generateRandomBytes(paddingLength - 1);

    return Uint8List.fromList([
      ...data,
      ...padding,
      paddingLength,
    ]);
  }

  /// Removes ISO 10126-2 padding.
  ///
  // Copies content to new array.
  static Uint8List removeISO10126(Uint8List data) {
    final int paddingLength = data.last;

    return data.sublist(0, data.length - paddingLength);
  }

  /// Adds ANSI X9.23 padding.
  ///
  /// [length] must be smaller than 255 due to limitations of ANSI X9.23 padding.
  /// Copies content to new array.
  static Uint8List addANSI({
    required Uint8List data,
    required int length,
  }) {
    // ANSI X9.23 can be only used with block size smaller than 255.
    assert(length <= 255);

    final int paddingLength = _getPaddingLength(
      dataLength: data.length,
      requiredLength: length,
    );

    final List<int> padding = List<int>.filled(
      paddingLength - 1,
      0,
    );

    return Uint8List.fromList([
      ...data,
      ...padding,
      paddingLength,
    ]);
  }

  /// Removes ANSI X9.23 padding.
  ///
  // Copies content to new array.
  static Uint8List removeANSI(Uint8List data) {
    final int paddingLength = data.last;

    return data.sublist(0, data.length - paddingLength);
  }
}
