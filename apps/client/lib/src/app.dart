import 'package:authenticator_vault/src/features/vault/vault_service.dart';
import 'package:authenticator_vault/src/features/vault/vault_home_page.dart';
import 'package:authenticator_vault/src/l10n.dart';
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

class VaultApp extends StatelessWidget {
  const VaultApp({required this.vaultService, super.key});

  final VaultService vaultService;

  @override
  Widget build(BuildContext context) {
    final service = vaultService;
    if (service is ProductivityVaultService) {
      return ValueListenableBuilder<AppPreferences>(
        valueListenable: service.preferences,
        builder: (_, preferences, _) => _buildApp(preferences),
      );
    }
    return _buildApp(const AppPreferences());
  }

  Widget _buildApp(AppPreferences preferences) {
    return MaterialApp(
      title: 'Authenticator Vault',
      debugShowCheckedModeBanner: false,
      locale: switch (preferences.language) {
        AppLanguage.zhHans => const Locale('zh', 'CN'),
        AppLanguage.english => const Locale('en'),
      },
      supportedLocales: AppStrings.supportedLocales,
      localizationsDelegates: const [
        AppStrings.delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
      ],
      themeMode: switch (preferences.theme) {
        AppThemePreference.system => ThemeMode.system,
        AppThemePreference.light => ThemeMode.light,
        AppThemePreference.dark => ThemeMode.dark,
      },
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
