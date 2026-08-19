import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('English localization asset is valid and contains core flows', () async {
    final source = await rootBundle.loadString('lib/l10n/app_en.arb');
    final messages = jsonDecode(source) as Map<String, Object?>;

    expect(messages['通用'], 'General');
    expect(messages['密码生成器'], 'Password generator');
    expect(messages['这个 Workspace 还没有 OTP'], isNotNull);
  });
}
