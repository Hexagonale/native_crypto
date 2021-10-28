import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:native_crypto/native_crypto.dart';

void main() {
  runApp(MyApp());
}

class MyApp extends StatefulWidget {
  @override
  _MyAppState createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        body: Center(
          child: TextButton(
            child: Text('Encrypt'),
            onPressed: () => _encrypt(),
          ),
        ),
      ),
    );
  }

  Future<void> _encrypt() async {
    final Uint8List key = Uint8List.fromList([
      0xba,
      0xf6,
      0x98,
      0xc1,
      0x64,
      0x50,
      0x11,
      0x7d,
      0xbe,
      0x6a,
      0xee,
      0x29,
      0x41,
      0x9e,
      0x15,
      0x53,
      0xd1,
      0xc3,
      0x9c,
      0xce,
      0x63,
      0xa0,
      0x80,
      0xad,
      0xfe,
      0xdd,
      0x22,
      0x9a,
      0x1d,
      0x9c,
      0x93,
      0x91
    ]);
    final AesCbcCipher cipher = AesCbcCipher();
    await cipher.init(
      forEncryption: true,
      key: key,
      initializationVector: Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8]),
    );

    // List<int> out = [];
    // cipher.stream.listen((Uint8List data) {
    //   out.addAll(data);
    // });

    // await cipher.add(
    //   Uint8List.fromList(
    //     [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8],
    //   ),
    // );
    // await cipher.close();

    // print(out.map((int i) => i.toRadixString(16)));

    const int size = 1024 * 1024 * 16;
    final Random random = new Random();
    final Uint8List data = Uint8List.fromList(List.generate(size, (_) => random.nextInt(255)));

    print('start');
    Stopwatch sw = Stopwatch();

    for (int i = 0; i < 16; i++) {
      sw.start();
      await cipher.add(data);
      sw.stop();

      final double avg = sw.elapsedMicroseconds / (i + 1) / 1000;
      print("\x1B[2J\x1B[0;0H");
      print('Take: $i, Avg: ${avg.toStringAsFixed(2)}');
      print('That gives ${(size / 1024 / 1024 / avg * 1000).toStringAsFixed(2)}MB/s');
    }

    await cipher.close();
  }
}
