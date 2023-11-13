import 'package:authenticator/home/provider/secret_list.dart';
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

class _SecretItemState extends State<SecretItem> {
  late Animation<double> _animation;
  late Animation<bool> _trigger;
  late Text _codeText;

  _SecretItemState();

  @override
  void initState() {
    _animation = Tween<double>(begin: 0, end: 1.0).animate(widget._controller);
    _trigger = Trigger().animate(widget._controller);

    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return Selector<SecretListProvider, Secret>(
        selector: (context, provider) => provider.get(widget._index),
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
                      secret.comment.isNotEmpty
                          ? secret.comment
                          : "${secret.label}(${secret.issuer})",
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
                        child: AnimatedBuilder(
                          animation: _trigger,
                          builder: (BuildContext context, Widget? child) {
                            if (_trigger.value) {
                              _codeText = _code(context);
                            }
                            return _codeText;
                          },
                        ),
                      ),
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

  Text _code(BuildContext context) {
    String code = Provider.of<SecretListProvider>(context, listen: false)
        .code(widget._index);
    return Text(
      code.isEmpty
          ? ""
          : "${code.substring(0, (code.length + 1) ~/ 2)} ${code.substring((code.length + 1) ~/ 2)}",
      textAlign: TextAlign.left,
      style: const TextStyle(color: Colors.lightBlueAccent, fontSize: 24),
    );
  }
}

class Trigger extends Animatable<bool> {
  bool trigger = true;
  double _pre = 0.0;

  @override
  bool transform(double t) {
    if (t < _pre || t == 0.0) {
      trigger = true;
    }
    _pre = t;
    bool res = trigger;
    trigger = false;
    return res;
  }
}
