import 'dart:io';

import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

bool get _isDesktop =>
    Platform.isLinux || Platform.isMacOS || Platform.isWindows;
bool _desktopWindowChromeEnabled = false;

Future<void> initializeDesktopWindowChrome() async {
  if (!_isDesktop) return;
  try {
    await windowManager.ensureInitialized();
    const options = WindowOptions(
      size: Size(1280, 800),
      minimumSize: Size(960, 640),
      center: true,
      titleBarStyle: TitleBarStyle.hidden,
      windowButtonVisibility: false,
      backgroundColor: Colors.transparent,
    );
    await windowManager.waitUntilReadyToShow(options, () async {
      await windowManager.show();
      await windowManager.focus();
    });
    _desktopWindowChromeEnabled = true;
  } on Object {
    // The native runner keeps its system title bar when custom chrome is unavailable.
  }
}

class DesktopTitleBar extends StatelessWidget {
  const DesktopTitleBar({
    required this.leading,
    required this.search,
    required this.actions,
    super.key,
  });

  final Widget leading;
  final Widget search;
  final List<Widget> actions;

  @override
  Widget build(BuildContext context) {
    final colors = Theme.of(context).colorScheme;
    final bar = LayoutBuilder(
      builder: (context, constraints) {
        final compact = constraints.maxWidth < 700;
        return ColoredBox(
          color: colors.surfaceContainerLow,
          child: SizedBox(
            height: _desktopWindowChromeEnabled && !compact ? 44 : 52,
            child: Row(
              children: [
                if (compact) Expanded(child: leading) else leading,
                if (!compact && _desktopWindowChromeEnabled)
                  Expanded(
                    child: DragToMoveArea(
                      child: Center(
                        child: ConstrainedBox(
                          constraints: const BoxConstraints(maxWidth: 440),
                          child: search,
                        ),
                      ),
                    ),
                  )
                else if (!compact) ...[
                  const Spacer(),
                  SizedBox(width: 160, child: search),
                ],
                ...actions,
                if (!compact && _desktopWindowChromeEnabled)
                  const _WindowButtons(),
                const SizedBox(width: 4),
              ],
            ),
          ),
        );
      },
    );
    return Column(children: [bar, const Divider(height: 1)]);
  }
}

class _WindowButtons extends StatelessWidget {
  const _WindowButtons();

  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      _WindowButton(
        tooltip: '最小化',
        icon: Icons.remove,
        onPressed: windowManager.minimize,
      ),
      _WindowButton(
        tooltip: '最大化或还原',
        icon: Icons.crop_square,
        onPressed: () async {
          if (await windowManager.isMaximized()) {
            await windowManager.unmaximize();
          } else {
            await windowManager.maximize();
          }
        },
      ),
      _WindowButton(
        tooltip: '关闭',
        icon: Icons.close,
        hoverColor: Theme.of(context).colorScheme.errorContainer,
        onPressed: windowManager.close,
      ),
    ],
  );
}

class _WindowButton extends StatelessWidget {
  const _WindowButton({
    required this.tooltip,
    required this.icon,
    required this.onPressed,
    this.hoverColor,
  });

  final String tooltip;
  final IconData icon;
  final Future<void> Function() onPressed;
  final Color? hoverColor;

  @override
  Widget build(BuildContext context) => Tooltip(
    message: tooltip,
    child: InkWell(
      hoverColor: hoverColor,
      onTap: onPressed,
      child: SizedBox(width: 42, height: 42, child: Icon(icon, size: 17)),
    ),
  );
}
