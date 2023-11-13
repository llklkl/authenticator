import 'package:flutter/material.dart';

const double _floatButtionSize = 56;
const double _floatButtionSmallSize = 42;

class Fab extends StatefulWidget {
  const Fab({
    super.key,
    this.onPressed,
    required this.children,
  });

  final List<ActionButton> children;
  final void Function()? onPressed;

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
    if (widget.onPressed != null) {
      widget.onPressed!();
    }
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
          child: Column(children: widget.children),
        ));
  }

  void buildModal(BuildContext context) {
    if (!_opened) {
      return;
    }
    Overlay.of(context).insert(OverlayEntry(builder: (context) {
      return ModalBarrier(
        color: Colors.grey.shade800.withAlpha(80),
        dismissible: false,
        onDismiss: _onToggle,
      );
    }));
  }

  @override
  void initState() {
    super.initState();
    _animationController =
        AnimationController(vsync: this, duration: _aniDutaion);
  }

  @override
  Widget build(BuildContext context) {
    // buildModal(context);
    return SizedBox.expand(
      child: Stack(alignment: Alignment.bottomRight, children: [
        Column(
          mainAxisAlignment: MainAxisAlignment.end,
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            buildOpenFab(context),
            buildCloseFab(context),
          ],
        )
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
      Container(
          padding: const EdgeInsets.fromLTRB(
              12, 12, (_floatButtionSize - _floatButtionSmallSize) / 2, 12),
          child: SizedBox.fromSize(
              size: _buttonSize,
              child: FloatingActionButton(
                onPressed: onPressed,
                child: icon,
              )))
    ]);
  }
}
