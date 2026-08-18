import 'package:authenticator_vault/src/app.dart';
import 'package:authenticator_vault/src/features/vault/desktop_title_bar.dart';
import 'package:authenticator_vault/src/features/vault/vault_service.dart';
import 'package:authenticator_vault/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await initializeDesktopWindowChrome();
  await RustLib.init();
  final vaultService = await NativeVaultService.create();
  runApp(VaultApp(vaultService: vaultService));
}
