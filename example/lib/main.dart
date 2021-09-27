import 'dart:convert';
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
    final Uint8List key = Uint8List.fromList(utf8.encode('super-secret-key'));
    final AesCbcCipher cipher = AesCbcCipher();
    cipher.init(
      forEncryption: true,
      key: key,
    );

    cipher.close();

    // final Random random = new Random();
    // final Uint8List data = Uint8List.fromList(List.generate(1024 * 1024 * 256, (_) => random.nextInt(255)));
    // final Uint8List iv = Uint8List.fromList(
    //   [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    // );

    // final int? id = await Crypto.create(key, iv, true);
    // if (id == null) {
    //   print('id is null');
    //   return;
    // }

    // print('start');
    // Stopwatch sw = Stopwatch();

    // for (int i = 0; i < 16; i++) {
    //   sw.start();
    //   await Crypto.writeBuffer(data);
    //   await Crypto.process(id);
    //   sw.stop();

    //   print("\x1B[2J\x1B[0;0H");
    //   print('Take: $i, Avg: ${(sw.elapsedMilliseconds / i).toStringAsFixed(2)}');
    // }
  }
}
