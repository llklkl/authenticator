import 'dart:typed_data';

import 'package:authenticator_vault/src/features/security/platform_security_service.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test(
    'content protection follows unlocked, modal, and background state',
    () async {
      final platform = _FakePlatformSecurity();
      final coordinator = SecurityCoordinator(platform);

      await coordinator.setUnlockedCount(1);
      await coordinator.setUnlockedCount(0);
      await coordinator.sensitive(() async {});
      await coordinator.setBackgrounded(true);
      await coordinator.setBackgrounded(false);

      expect(platform.protectionChanges, [
        true,
        false,
        true,
        false,
        true,
        false,
      ]);
    },
  );

  test('auto-lock uses the configured monotonic elapsed threshold', () {
    expect(
      shouldAutoLock(
        hasUnlockedWorkspaces: true,
        backgroundElapsed: Duration.zero,
        timeoutSeconds: 0,
      ),
      isTrue,
    );
    expect(
      shouldAutoLock(
        hasUnlockedWorkspaces: true,
        backgroundElapsed: const Duration(seconds: 299),
        timeoutSeconds: 300,
      ),
      isFalse,
    );
    expect(
      shouldAutoLock(
        hasUnlockedWorkspaces: true,
        backgroundElapsed: const Duration(seconds: 300),
        timeoutSeconds: 300,
      ),
      isTrue,
    );
    expect(
      shouldAutoLock(
        hasUnlockedWorkspaces: false,
        backgroundElapsed: const Duration(hours: 1),
        timeoutSeconds: 30,
      ),
      isFalse,
    );
  });

  test('secret byte buffers are overwritten after platform handoff', () {
    final bytes = Uint8List.fromList([1, 2, 3, 4]);
    eraseBytes(bytes);
    expect(bytes, everyElement(0));
  });
}

class _FakePlatformSecurity implements PlatformSecurityService {
  final protectionChanges = <bool>[];

  @override
  Stream<void> get screenOffEvents => const Stream.empty();

  @override
  Future<bool> canAuthenticateStrong() async => true;

  @override
  Future<void> clearKeyring() async {}

  @override
  Future<bool> hasKeyring() async => false;

  @override
  Future<void> sealKeyring(Uint8List keyring) async {}

  @override
  Future<void> setContentProtected(bool protected) async {
    protectionChanges.add(protected);
  }

  @override
  Future<Uint8List> unsealKeyring() async => Uint8List(0);
}
