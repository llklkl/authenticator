import 'package:flutter/material.dart';

class SecretItem extends StatefulWidget {
  const SecretItem({super.key});

  @override
  State<SecretItem> createState() => _SecretItemState();
}

class _SecretItemState extends State<SecretItem> with TickerProviderStateMixin {
  String name = "Jump Seddddddd";
  String comment =
      "zzzddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
  String code = "123";
  double process = 0;
  late AnimationController _controller;

  _SecretItemState();

  @override
  void initState() {
    _controller =
        AnimationController(vsync: this, duration: const Duration(seconds: 3))
          ..addListener(() {
            setState(() {});
          })
          ..repeat(reverse: false);
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
        decoration: BoxDecoration(
            color: Colors.white38, borderRadius: BorderRadius.circular(8)),
        child: Column(
            mainAxisAlignment: MainAxisAlignment.start,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.start,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                      child: Text(
                    Characters("$name($comment)").join('\u{200B}'),
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
                      code.isEmpty
                          ? ""
                          : "${code.substring(0, (code.length + 1) ~/ 2)} ${code.substring((code.length + 1) ~/ 2)}",
                      textAlign: TextAlign.left,
                      style: const TextStyle(
                          color: Colors.lightBlueAccent, fontSize: 24),
                    )),
                    Padding(
                      padding: const EdgeInsets.only(right: 8.0),
                      child: SizedBox(
                          height: 16,
                          width: 16,
                          child: CircularProgressIndicator(
                            value: _controller.value,
                          )),
                    ),
                  ],
                ),
              ),
            ]));
  }
}
