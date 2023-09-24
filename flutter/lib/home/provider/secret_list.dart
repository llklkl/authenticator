import 'package:authenticator/repo/secret_repo.dart';
import 'package:flutter/foundation.dart';
import 'package:authenticator/home/model/secret.dart';

class SecretListProvider extends ChangeNotifier {
  late List<Secret> _list = [];
  int _length = 0;

  List<Secret> get list => _list;

  void add(Secret secret) {
    SecretRepo.repo.insert(secret);
    notifyListeners();
  }

  Future load() {
    print("load all secret from db");
    return SecretRepo.repo.getAll().then((value) {
      _list = value;
      _length = _list.length;
      notifyListeners();
      print("load secret done");
    });
  }

  Secret get(int index) {
    return _list[index];
  }

  int length() {
    return _length;
  }

  String code(int index) {
    return "123456";
  }
}
