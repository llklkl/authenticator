import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

abstract interface class PlatformSecurityService {
  Stream<void> get screenOffEvents;
  Future<bool> canAuthenticateStrong();
  Future<bool> hasKeyring();
  Future<void> sealKeyring(Uint8List keyring);
  Future<Uint8List> unsealKeyring();
  Future<void> clearKeyring();
  Future<void> setContentProtected(bool protected);
}

class PlatformSecurityFailure implements Exception {
  const PlatformSecurityFailure(this.code);
  final String code;
  bool get isKeyInvalidated => code == 'keyInvalidated';
}

class NoopPlatformSecurityService implements PlatformSecurityService {
  const NoopPlatformSecurityService();

  @override
  Stream<void> get screenOffEvents => const Stream.empty();
  @override
  Future<bool> canAuthenticateStrong() async => false;
  @override
  Future<bool> hasKeyring() async => false;
  @override
  Future<void> sealKeyring(Uint8List keyring) async =>
      throw const PlatformSecurityFailure('notAvailable');
  @override
  Future<Uint8List> unsealKeyring() async =>
      throw const PlatformSecurityFailure('notAvailable');
  @override
  Future<void> clearKeyring() async {}
  @override
  Future<void> setContentProtected(bool protected) async {}
}

class MethodChannelSecurityService implements PlatformSecurityService {
  MethodChannelSecurityService({MethodChannel? methods, EventChannel? events})
    : _methods = methods ?? const MethodChannel(_methodName),
      _events = events ?? const EventChannel(_eventName);

  static const _methodName = 'top.llklkl.authenticatorvault/security';
  static const _eventName = 'top.llklkl.authenticatorvault/security_events';
  final MethodChannel _methods;
  final EventChannel _events;

  @override
  Stream<void> get screenOffEvents {
    if (defaultTargetPlatform != TargetPlatform.android) {
      return const Stream<void>.empty();
    }
    return _events
        .receiveBroadcastStream()
        .where((event) {
          return event == 'screenOff';
        })
        .map((_) {});
  }

  @override
  Future<bool> canAuthenticateStrong() => _bool('canAuthenticateStrong');

  @override
  Future<bool> hasKeyring() => _bool('hasKeyring');

  Future<bool> _bool(String method) async {
    if (defaultTargetPlatform != TargetPlatform.android) return false;
    return await _invoke<bool>(method) ?? false;
  }

  @override
  Future<void> sealKeyring(Uint8List keyring) async {
    await _invoke<void>('sealKeyring', keyring);
  }

  @override
  Future<Uint8List> unsealKeyring() async {
    final value = await _invoke<Uint8List>('unsealKeyring');
    if (value == null) throw const PlatformSecurityFailure('storageFailure');
    return value;
  }

  @override
  Future<void> clearKeyring() => _invoke<void>('clearKeyring');

  @override
  Future<void> setContentProtected(bool protected) =>
      _invoke<void>('setContentProtected', protected);

  Future<T?> _invoke<T>(String method, [Object? arguments]) async {
    if (defaultTargetPlatform != TargetPlatform.android) {
      if (method == 'setContentProtected' || method == 'clearKeyring') {
        return null;
      }
      throw const PlatformSecurityFailure('notAvailable');
    }
    try {
      return await _methods.invokeMethod<T>(method, arguments);
    } on PlatformException catch (error) {
      throw PlatformSecurityFailure(error.code);
    }
  }
}

class SecurityCoordinator {
  SecurityCoordinator(this._platform);
  final PlatformSecurityService _platform;
  int _unlockedCount = 0;
  int _sensitiveDepth = 0;
  bool _backgrounded = false;
  bool _lastProtected = false;

  Future<void> setUnlockedCount(int count) async {
    _unlockedCount = count;
    await _apply();
  }

  Future<T> sensitive<T>(Future<T> Function() operation) async {
    _sensitiveDepth += 1;
    await _apply();
    try {
      return await operation();
    } finally {
      _sensitiveDepth -= 1;
      await _apply();
    }
  }

  Future<void> setBackgrounded(bool value) async {
    _backgrounded = value;
    await _apply();
  }

  Future<void> _apply() async {
    final value = _unlockedCount > 0 || _sensitiveDepth > 0 || _backgrounded;
    if (value == _lastProtected) return;
    _lastProtected = value;
    await _platform.setContentProtected(value);
  }
}

void eraseBytes(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);

bool shouldAutoLock({
  required bool hasUnlockedWorkspaces,
  required Duration backgroundElapsed,
  required int timeoutSeconds,
}) =>
    hasUnlockedWorkspaces &&
    (timeoutSeconds == 0 ||
        backgroundElapsed >= Duration(seconds: timeoutSeconds));
