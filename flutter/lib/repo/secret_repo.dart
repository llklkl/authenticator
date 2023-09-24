import 'package:authenticator/home/model/secret.dart';
import 'package:authenticator/repo/dbhelper.dart';
import 'package:authenticator/repo/tables.dart';
import 'package:sqflite/sqflite.dart';

class SecretRepo {
  SecretRepo._internal();

  static final SecretRepo repo = SecretRepo._internal();

  Future<int> insert(Secret secret) async {
    Database db = DBHelper.dbHelper.db;
    return db.insert(Tables.secretTableName, secret.toMap());
  }

  Future<List<Secret>> getAll() async {
    Database db = DBHelper.dbHelper.db;
    var res = await db.query(Tables.secretTableName);

    List<Secret> list =
        res.isEmpty ? [] : res.map((item) => Secret.fromMap(item)).toList();
    return list;
  }
}
