import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

class AppStrings {
  const AppStrings(this.locale, this._messages);

  final Locale locale;
  final Map<String, String> _messages;

  static AppStrings of(BuildContext context) =>
      Localizations.of<AppStrings>(context, AppStrings)!;

  String text(String source, [Map<String, Object> values = const {}]) {
    var result = _messages[source] ?? source;
    for (final entry in values.entries) {
      result = result.replaceAll('{${entry.key}}', entry.value.toString());
    }
    return result;
  }

  static const delegate = _AppStringsDelegate();
  static const supportedLocales = [Locale('zh', 'CN'), Locale('en')];
}

class _AppStringsDelegate extends LocalizationsDelegate<AppStrings> {
  const _AppStringsDelegate();

  @override
  bool isSupported(Locale locale) => AppStrings.supportedLocales.any(
    (item) => item.languageCode == locale.languageCode,
  );

  @override
  Future<AppStrings> load(Locale locale) async {
    final source = await rootBundle.loadString(
      'lib/l10n/app_${locale.languageCode}.arb',
    );
    final decoded = jsonDecode(source) as Map<String, Object?>;
    return AppStrings(
      locale,
      decoded.map((key, value) => MapEntry(key, value is String ? value : key)),
    );
  }

  @override
  bool shouldReload(_AppStringsDelegate old) => false;
}

extension AppStringsContext on BuildContext {
  AppStrings get l10n => AppStrings.of(this);
  String tr(String source, [Map<String, Object> values = const {}]) =>
      l10n.text(source, values);
}
