import 'package:authenticator/repo/secret_repo.dart';
import 'package:flutter/foundation.dart';
import 'package:authenticator/home/model/secret.dart';

class SecretListProvider extends ChangeNotifier {
  List<Secret> _list = [];

  void add(Secret secret) {
    SecretRepo.repo.insert(secret);
    notifyListeners();
  }

  Future load() {
    return SecretRepo.repo.getAll().then((value) {
      _list = value;
      notifyListeners();
    });
  }

  Secret get(int index) {
    return _list[index];
  }

  int length() {
    return _list.length;
  }

  String code(int index) {
    return "123456";
  }
}
