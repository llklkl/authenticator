import 'package:flutter/widgets.dart';
import 'package:authenticator/model/secret.dart';

class SecretListProvider extends ChangeNotifier  {

  List<Secret> _list = [];

  List<Secret> get list => _list;

  void add(Secret secret) {
    _list.add(secret);
    notifyListeners();
  }
}
