import 'dart:convert';
import 'dart:io';

import 'package:authenticator_vault/src/features/security/platform_security_service.dart';
import 'package:authenticator_vault/src/features/vault/vault_service.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
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
      expect(versioned['version'], 1);
      expect(versioned['autoLockSeconds'], 300);
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
}
