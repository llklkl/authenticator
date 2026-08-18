import 'package:authenticator_vault/src/features/vault/vault_service.dart';
import 'package:authenticator_vault/src/features/vault/vault_home_page.dart';
import 'package:flutter/material.dart';

class VaultApp extends StatelessWidget {
  const VaultApp({required this.vaultService, super.key});

  final VaultService vaultService;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Authenticator Vault',
      debugShowCheckedModeBanner: false,
      themeMode: ThemeMode.system,
      theme: _theme(Brightness.light),
      darkTheme: _theme(Brightness.dark),
      home: VaultHomePage(vaultService: vaultService),
    );
  }

  ThemeData _theme(Brightness brightness) {
    final scheme = ColorScheme.fromSeed(
      seedColor: const Color(0xff3d716b),
      brightness: brightness,
      dynamicSchemeVariant: DynamicSchemeVariant.fidelity,
    );
    return ThemeData(
      colorScheme: scheme,
      useMaterial3: true,
      visualDensity: VisualDensity.compact,
      scaffoldBackgroundColor: scheme.surface,
      cardTheme: const CardThemeData(elevation: 0, margin: EdgeInsets.zero),
      inputDecorationTheme: InputDecorationTheme(
        border: OutlineInputBorder(borderRadius: BorderRadius.circular(8)),
      ),
      dividerTheme: DividerThemeData(color: scheme.outlineVariant),
    );
  }
}
