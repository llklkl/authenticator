import 'package:authenticator_vault/src/features/vault/vault_service.dart';
import 'package:authenticator_vault/src/features/vault/vault_home_page.dart';
import 'package:flutter/material.dart';

class VaultApp extends StatelessWidget {
  const VaultApp({required this.vaultService, super.key});

  final VaultService vaultService;

  @override
  Widget build(BuildContext context) {
    final colorScheme = ColorScheme.fromSeed(
      seedColor: const Color(0xff315da8),
      brightness: Brightness.light,
    );
    return MaterialApp(
      title: 'Authenticator Vault',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: colorScheme,
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xfff7f8fa),
        cardTheme: const CardThemeData(elevation: 0, margin: EdgeInsets.zero),
        inputDecorationTheme: const InputDecorationTheme(
          border: OutlineInputBorder(),
        ),
      ),
      home: VaultHomePage(vaultService: vaultService),
    );
  }
}
