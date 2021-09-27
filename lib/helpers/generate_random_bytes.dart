import 'dart:math';
import 'dart:typed_data';

Uint8List generateRandomBytes(int length) {
  final Random random = new Random.secure();

  return Uint8List.fromList(
    List<int>.generate(
      length,
      (_) => random.nextInt(255),
    ),
  );
}
