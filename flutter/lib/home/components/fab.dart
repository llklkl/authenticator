import 'package:flutter/material.dart';

const double _floatButtionSize = 56;
const double _floatButtionSmallSize = 42;

class Fab extends StatefulWidget {
  const Fab({
    super.key,
    required this.children,
  });

  final List<ActionButton> children;

  @override
  State<Fab> createState() => _FabState();
}

class _FabState extends State<Fab> with SingleTickerProviderStateMixin {
  _FabState();

  final Size _buttionSize = const Size(_floatButtionSize, _floatButtionSize);
  final Duration _aniDutaion = const Duration(milliseconds: 150);

  bool _opened = false;

  late AnimationController _animationController;

  void _onToggle() {
    setState(() {
      if (!_opened) {
        _animationController.forward();
      } else {
        _animationController.reverse();
      }
      _opened = !_opened;
    });
  }

  Widget buildCloseFab(BuildContext context) {
    return SizedBox.fromSize(
      size: _buttionSize,
      child: RotationTransition(
          turns: Tween<double>(begin: 0, end: 3.0 / 8)
              .animate(_animationController),
          child: FloatingActionButton(
            onPressed: _onToggle,
            child: const Icon(Icons.add),
          )),
    );
  }

  Widget buildOpenFab(BuildContext context) {
    return AnimatedOpacity(
        opacity: _opened ? 1 : 0,
        duration: _aniDutaion,
        child: IgnorePointer(
          ignoring: !_opened,
          child: Wrap(
            direction: Axis.vertical,
            spacing: 18,
            children: widget.children,
          ),
        ));
  }

  Widget buildModal(BuildContext context) {
    return AnimatedOpacity(
      duration: _aniDutaion,
      opacity: _opened ? 1 : 0,
      child: ModalBarrier(
        dismissible: _opened,
        onDismiss: _onToggle,
        color: Colors.black.withOpacity(0.2),
      ),
    );
  }

  @override
  void initState() {
    super.initState();
    _animationController =
        AnimationController(vsync: this, duration: _aniDutaion);
  }

  @override
  Widget build(BuildContext context) {
    return SizedBox.expand(
      child: Stack(alignment: Alignment.bottomRight, children: [
        if (_opened) buildModal(context),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 48),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.end,
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Padding(
                padding: const EdgeInsets.only(bottom: 18),
                child: buildOpenFab(context),
              ),
              buildCloseFab(context),
            ],
          ),
        ),
      ]),
    );
  }
}

class ActionButton extends StatelessWidget {
  const ActionButton({
    super.key,
    this.onPressed,
    this.tips,
    required this.icon,
  });

  final VoidCallback? onPressed;
  final Widget icon;
  final Text? tips;
  final Size _buttonSize =
      const Size(_floatButtionSmallSize, _floatButtionSmallSize);

  @override
  Widget build(BuildContext context) {
    return Row(mainAxisAlignment: MainAxisAlignment.end, children: [
      if (tips != null)
        Container(
          decoration: BoxDecoration(
            color: Theme.of(context).primaryColor,
            borderRadius: BorderRadius.circular(4),
            boxShadow: [
              BoxShadow(
                offset: const Offset(0, 3),
                blurRadius: 6,
                color: Colors.black.withOpacity(0.3),
              )
            ],
          ),
          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 4),
          clipBehavior: Clip.antiAlias,
          child: tips,
        ),
      Padding(
          padding: const EdgeInsets.only(
            left: 18,
            right: (_floatButtionSize - _floatButtionSmallSize) / 2,
          ),
          child: SizedBox.fromSize(
              size: _buttonSize,
              child: FloatingActionButton(
                onPressed: onPressed,
                child: icon,
              )))
    ]);
  }
}
