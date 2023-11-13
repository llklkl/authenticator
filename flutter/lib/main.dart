import 'dart:io';

import 'package:authenticator/ffi/bridge_gen.dart';
import 'package:authenticator/home/main_page.dart';
import 'package:authenticator/repo/dbhelper.dart';
import 'package:flutter/material.dart';
import 'package:path/path.dart' as path;
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:path_provider/path_provider.dart';

import 'ffi/ffi.dart' as ffi;

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  // Initialize FFI
  if (!Platform.isAndroid && !Platform.isIOS) {
    sqfliteFfiInit();
    databaseFactory = databaseFactoryFfi;
  }
  await DBHelper.dbHelper.init();
  await initApp();
  runApp(const AuthenticatorApp());
}

Future<String> getDbPath() async {
  return getApplicationSupportDirectory().then((value) {
    return path.join(value.path, "authenticator.db");
  });
}

Future initApp() async {
  return getDbPath().then((dbPath) {
    ffi.Api.init(cfg: AppConfig(dbPath: dbPath));
  });
}

class AuthenticatorApp extends StatelessWidget {
  const AuthenticatorApp({super.key});

  // This widget is the root of your application.
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
