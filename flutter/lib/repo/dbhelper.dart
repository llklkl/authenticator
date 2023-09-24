import 'dart:async';

import 'package:authenticator/repo/tables.dart';
import 'package:flutter/foundation.dart';
import 'package:path/path.dart';
import 'package:sqflite/sqflite.dart';

class DBHelper {
  late Database _db;

  static int get version => 1;

  static const String _databaseName = "authenticator.db";

  DBHelper._internal();

  static final dbHelper = DBHelper._internal();

  Database get db => _db;

  Future init() async {
    _db = await _open();
    _createTables();
    print("init");
  }

  Future<Database> _open() async {
    // return openDatabase(join(await getDatabasesPath(), _databaseName))
    //     .then((db) async {
    //   _db = db;
    //   if (kDebugMode) {
    //     print("path: ${join(await getDatabasesPath(), _databaseName)}");
    //     print("database opened, try create tables");
    //   }
    //   await _createTables();
    // }).catchError((err) {
    //   if (kDebugMode) {
    //     print("open database failed, $err");
    //   }
    // });
    getDatabasesPath().then((value) {
      print("$value");
    });
    return openDatabase(join(await getDatabasesPath(), _databaseName));
  }

  Future _createTables() async {
    return _db.execute(Tables.secretTableScheme).then((_) {
      if (kDebugMode) {
        print("create tables success");
      }
    }).catchError((err) {
      if (kDebugMode) {
        print("create tables failed, $err");
      }
    });
  }

  Future close() async {
    _db.close();
  }
}
