import 'package:authenticator/components/secret_item.dart';
import 'package:authenticator/provider/secret_list.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

class SecretList extends StatefulWidget {
  const SecretList({super.key});

  @override
  State<SecretList> createState() => _SecretListState();
}

class _SecretListState extends State<SecretList>
    with SingleTickerProviderStateMixin {
  final Map<int, AnimationController> _aniController = {};

  AnimationController getController(BuildContext context, int index) {
    var secret =
        Provider.of<SecretListProvider>(context, listen: false).list[index];
    if (!_aniController.containsKey(secret.refreshPeriod)) {
      _aniController[secret.refreshPeriod] = AnimationController(
          vsync: this, duration: Duration(seconds: secret.refreshPeriod))
        ..repeat(reverse: false);
    }

    return _aniController[secret.refreshPeriod]!;
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<SecretListProvider>(builder: (context, provider, child) {
      return ListView.separated(
          itemCount: provider.list.length,
          separatorBuilder: (context,_){
            return const Divider();
          },
          itemBuilder: (context, index) {
            return SecretItem(index, getController(context, index));
          });
    });
  }
}
