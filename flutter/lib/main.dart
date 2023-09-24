import 'dart:io';

import 'package:authenticator/home/main_page.dart';
import 'package:authenticator/repo/dbhelper.dart';
import 'package:flutter/material.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Initialize FFI
  if (!Platform.isAndroid && !Platform.isIOS) {
    sqfliteFfiInit();
    databaseFactory = databaseFactoryFfi;
  }
  await DBHelper.dbHelper.init();
  runApp(const AuthenticatorApp());
}

class AuthenticatorApp extends StatelessWidget {
  const AuthenticatorApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '身份验证器',
      theme: ThemeData(
        primarySwatch: Colors.orange,
      ),
      home: const MainPage(),
    );
  }
}
