// The original content is temporarily commented out to allow generating a self-contained demo - feel free to uncomment later.

import 'dart:io';

import 'package:authenticator/home/main_page.dart';
import 'package:authenticator/repo/dbhelper.dart';
import 'package:flutter/material.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:path_provider/path_provider.dart';
import 'package:authenticator/src/rust/api/api.dart' as api;
import 'package:authenticator/src/rust/frb_generated.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Initialize FFI
  if (!Platform.isAndroid && !Platform.isIOS) {
    sqfliteFfiInit();
    databaseFactory = databaseFactoryFfi;
  }
  await RustLib.init();

  await DBHelper.dbHelper.init();
  await initApp();

  print(api.appinfo(name: "hello"));

  runApp(const AuthenticatorApp());
}

Future<String> getDbPath() async {
  return getApplicationSupportDirectory().then((value) {
    return value.path;
  });
}

Future<void> initApp() async {
  var dataPath = await getDbPath();
  return api.init(dataPath: dataPath);
}

class AuthenticatorApp extends StatelessWidget {
  const AuthenticatorApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '身份验证器',
      theme: ThemeData(
          primarySwatch: Colors.orange, fontFamily: "Microsoft YaHei UI"),
      home: const MainPage(),
    );
  }
}
