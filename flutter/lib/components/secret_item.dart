import 'package:authenticator/provider/secret_list.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../model/secret.dart';

class SecretItem extends StatefulWidget {
  const SecretItem(this._index, this._controller, {super.key});

  final int _index;
  final AnimationController _controller;

  @override
  State<SecretItem> createState() => _SecretItemState();
}

class _SecretItemState extends State<SecretItem> with TickerProviderStateMixin {
  late Animation<double> _animation;

  _SecretItemState();

  @override
  void initState() {
    _animation =
        Tween<double>(begin: 0.0, end: 1.0).animate(widget._controller);
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return Selector<SecretListProvider, Secret>(
        selector: (context, provider) => provider.list[widget._index],
        builder: (context, secret, child) {
          return Column(
              mainAxisAlignment: MainAxisAlignment.start,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.start,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(
                        child: Text(
                      "${secret.name}(${secret.comment})",
                      textAlign: TextAlign.left,
                      softWrap: true,
                      overflow: TextOverflow.ellipsis,
                      maxLines: 1,
                      style: const TextStyle(color: Colors.black, fontSize: 18),
                    )),
                  ],
                ),
                Padding(
                  padding: const EdgeInsets.only(top: 4.0),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.start,
                    crossAxisAlignment: CrossAxisAlignment.center,
                    children: [
                      Expanded(
                          child: Text(
                        secret.code.isEmpty
                            ? ""
                            : "${secret.code.substring(0, (secret.code.length + 1) ~/ 2)} ${secret.code.substring((secret.code.length + 1) ~/ 2)}",
                        textAlign: TextAlign.left,
                        style: const TextStyle(
                            color: Colors.lightBlueAccent, fontSize: 24),
                      )),
                      Padding(
                          padding: const EdgeInsets.only(right: 8.0),
                          child: SizedBox(
                            height: 16,
                            width: 16,
                            child: AnimatedBuilder(
                              animation: _animation,
                              builder: (BuildContext context, Widget? child) {
                                return CircularProgressIndicator(
                                  value: _animation.value,
                                );
                              },
                            ),
                          )),
                    ],
                  ),
                ),
              ]);
        });
  }
}
