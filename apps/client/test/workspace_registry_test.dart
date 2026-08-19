import 'dart:convert';
import 'dart:io';

import 'package:authenticator_vault/src/features/security/platform_security_service.dart';
import 'package:authenticator_vault/src/features/vault/vault_service.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

void main() {
  test('workspace name defaults to the selected KDBX file name', () {
    expect(suggestWorkspaceName('/home/user/Documents/密码.kdbx'), '密码');
    expect(suggestWorkspaceName(r'C:\Users\user\Work.KDBX'), 'Work');
  });

  test(
    'legacy registry migrates to versioned UUID records with backup',
    () async {
      final directory = await Directory.systemTemp.createTemp(
        'vault-registry-',
      );
      addTearDown(() => directory.delete(recursive: true));
      final registry = File('${directory.path}/workspaces.json');
      await registry.writeAsString(
        jsonEncode([
          {'id': 'legacy-id', 'name': 'Personal', 'path': '/vault.kdbx'},
        ]),
      );
      const migratedId = '018f47d2-c215-7b71-9c1d-7af181fef264';
      final service = NativeVaultService.forTesting(
        registryFile: registry,
        vaultDirectory: directory,
        platformSecurity: const NoopPlatformSecurityService(),
        newWorkspaceId: () => migratedId,
      );

      final workspaces = await service.loadWorkspaces();

      expect(workspaces.single.id, migratedId);
      expect(await File('${registry.path}.bak').exists(), isTrue);
      final versioned = jsonDecode(await registry.readAsString()) as Map;
      expect(versioned['version'], 3);
      expect(versioned['autoLockSeconds'], 300);
      expect(versioned['stalePasswordDays'], 180);
      expect(versioned['themeMode'], 'system');
      expect(versioned['locale'], 'zh_CN');
      expect(versioned['passwordSymbols'], isNotEmpty);
    },
  );

  test('corrupt registry fails closed without overwriting source', () async {
    final directory = await Directory.systemTemp.createTemp('vault-registry-');
    addTearDown(() => directory.delete(recursive: true));
    final registry = File('${directory.path}/workspaces.json');
    const source = '{not-json';
    await registry.writeAsString(source);
    final service = NativeVaultService.forTesting(
      registryFile: registry,
      vaultDirectory: directory,
      platformSecurity: const NoopPlatformSecurityService(),
      newWorkspaceId: () => 'unused',
    );

    await expectLater(
      service.loadWorkspaces(),
      throwsA(isA<WorkspaceRegistryException>()),
    );
    expect(await registry.readAsString(), source);
  });

  test('WebDAV password is excluded from the workspace registry', () async {
    FlutterSecureStorage.setMockInitialValues({});
    final directory = await Directory.systemTemp.createTemp('vault-registry-');
    addTearDown(() => directory.delete(recursive: true));
    final registry = File('${directory.path}/workspaces.json');
    const workspace = WorkspaceInfo(
      id: '018f47d2-c215-7b71-9c1d-7af181fef264',
      name: 'Personal',
      path: '/vault.kdbx',
    );
    await registry.writeAsString(
      jsonEncode({
        'version': 2,
        'autoLockSeconds': 300,
        'stalePasswordDays': 180,
        'workspaces': [workspace.toJson()],
      }),
    );
    final service = NativeVaultService.forTesting(
      registryFile: registry,
      vaultDirectory: directory,
      platformSecurity: const NoopPlatformSecurityService(),
      newWorkspaceId: () => 'unused',
    );
    final loaded = (await service.loadWorkspaces()).single;
    await service.saveWorkspaceSync(
      loaded,
      const WorkspaceSyncSettings(
        endpoint: 'https://dav.example.test/vault.kdbx',
        username: 'alice',
        passwordStored: true,
      ),
      password: 'webdav-secret-value',
    );

    final source = await registry.readAsString();
    expect(source, isNot(contains('webdav-secret-value')));
    expect(source, contains('passwordStored'));
    expect(
      await const FlutterSecureStorage().read(
        key:
            'authenticator_vault.webdav.'
            '${workspace.id}.password',
      ),
      'webdav-secret-value',
    );
    final migrated = jsonDecode(await registry.readAsString()) as Map;
    expect(migrated['version'], 3);
  });

  test('application preferences persist in registry version 3', () async {
    final directory = await Directory.systemTemp.createTemp('vault-registry-');
    addTearDown(() => directory.delete(recursive: true));
    final registry = File('${directory.path}/workspaces.json');
    await registry.writeAsString(
      jsonEncode({
        'version': 2,
        'autoLockSeconds': 300,
        'stalePasswordDays': 180,
        'workspaces': <Object>[],
      }),
    );
    String normalize(String value) {
      if (value.isEmpty ||
          value.codeUnits.any((code) => code < 33 || code > 126)) {
        throw const FormatException();
      }
      return value;
    }

    final service = NativeVaultService.forTesting(
      registryFile: registry,
      vaultDirectory: directory,
      platformSecurity: const NoopPlatformSecurityService(),
      newWorkspaceId: () => 'unused',
      normalizePasswordSymbols: normalize,
    );
    await service.loadWorkspaces();
    await service.setThemePreference(AppThemePreference.dark);
    await service.setLanguage(AppLanguage.english);
    await service.setPasswordSymbols('@#');

    final reloaded = NativeVaultService.forTesting(
      registryFile: registry,
      vaultDirectory: directory,
      platformSecurity: const NoopPlatformSecurityService(),
      newWorkspaceId: () => 'unused',
      normalizePasswordSymbols: normalize,
    );
    await reloaded.loadWorkspaces();
    expect(reloaded.preferences.value.theme, AppThemePreference.dark);
    expect(reloaded.preferences.value.language, AppLanguage.english);
    expect(reloaded.preferences.value.passwordSymbols, '@#');
  });
}
