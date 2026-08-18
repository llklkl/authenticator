import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:authenticator_vault/src/features/security/platform_security_service.dart';
import 'package:authenticator_vault/src/rust/api/simple.dart' as native;
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';

enum EntryType { login, otp, recoveryCodes, secureNote }

class WorkspaceInfo {
  const WorkspaceInfo({
    required this.id,
    required this.name,
    required this.path,
    this.quickUnlockEnvelope,
  });

  final String id;
  final String name;
  final String path;
  final Uint8List? quickUnlockEnvelope;

  bool get quickUnlockEnabled => quickUnlockEnvelope != null;

  Map<String, Object> toJson() => {
    'id': id,
    'name': name,
    'path': path,
    if (quickUnlockEnvelope case final envelope?)
      'quickUnlockEnvelope': base64Encode(envelope),
  };

  factory WorkspaceInfo.fromJson(Map<String, Object?> json) => WorkspaceInfo(
    id: json['id']! as String,
    name: json['name']! as String,
    path: json['path']! as String,
    quickUnlockEnvelope: switch (json['quickUnlockEnvelope']) {
      final String value => Uint8List.fromList(base64Decode(value)),
      _ => null,
    },
  );

  WorkspaceInfo copyWith({
    Uint8List? quickUnlockEnvelope,
    bool clear = false,
  }) => WorkspaceInfo(
    id: id,
    name: name,
    path: path,
    quickUnlockEnvelope: clear
        ? null
        : quickUnlockEnvelope ?? this.quickUnlockEnvelope,
  );
}

class UnlockedWorkspace {
  const UnlockedWorkspace({required this.workspace, required this.handleId});

  final WorkspaceInfo workspace;
  final BigInt handleId;
}

class VaultEntryItem {
  const VaultEntryItem({
    required this.id,
    required this.type,
    required this.title,
    required this.username,
    required this.url,
    required this.hasPassword,
    required this.hasOtp,
    required this.tags,
  });

  final String id;
  final EntryType type;
  final String title;
  final String username;
  final String url;
  final bool hasPassword;
  final bool hasOtp;
  final List<String> tags;
}

class VaultEntryDraft {
  const VaultEntryDraft({
    required this.type,
    required this.title,
    this.username = '',
    this.password = '',
    this.url = '',
    this.notes = '',
    this.tags = const [],
    this.otpUri,
    this.preserveExistingOtp = false,
  });

  final EntryType type;
  final String title;
  final String username;
  final String password;
  final String url;
  final String notes;
  final List<String> tags;
  final String? otpUri;
  final bool preserveExistingOtp;
}

class OtpValue {
  const OtpValue({required this.code, this.validForSeconds});

  final String code;
  final int? validForSeconds;
}

class WebDavSettings {
  const WebDavSettings({
    required this.endpoint,
    required this.username,
    required this.password,
    this.allowInsecureHttp = false,
  });

  final String endpoint;
  final String username;
  final String password;
  final bool allowInsecureHttp;
}

class SyncSummary {
  const SyncSummary({required this.attempts, required this.merged});
  final int attempts;
  final bool merged;
}

abstract interface class VaultService {
  Future<List<WorkspaceInfo>> loadWorkspaces();
  Future<String?> chooseKdbxFile();
  Future<UnlockedWorkspace> createWorkspace(String name, String password);
  Future<UnlockedWorkspace> importWorkspace(
    String name,
    String path,
    String password,
  );
  Future<BigInt> unlock(WorkspaceInfo workspace, String password);
  Future<void> lockAll();
  Future<List<VaultEntryItem>> listEntries(BigInt handleId);
  Future<void> createEntry(BigInt handleId, VaultEntryDraft draft);
  Future<void> updateEntry(
    BigInt handleId,
    String entryId,
    VaultEntryDraft draft,
  );
  Future<void> deleteEntry(BigInt handleId, String entryId);
  Future<String> revealPassword(BigInt handleId, String entryId);
  Future<String> revealNotes(BigInt handleId, String entryId);
  Future<OtpValue> currentOtp(BigInt handleId, String entryId, DateTime now);
  Future<void> importOtp(BigInt handleId, String uri);
  Future<SyncSummary> syncWebDav(
    BigInt handleId,
    String workspaceId,
    WebDavSettings settings,
  );
}

class QuickUnlockOutcome {
  const QuickUnlockOutcome({required this.opened, required this.failedIds});
  final List<UnlockedWorkspace> opened;
  final List<String> failedIds;
}

abstract interface class SecurityVaultService implements VaultService {
  PlatformSecurityService get platformSecurity;
  int get autoLockSeconds;
  Future<void> setAutoLockSeconds(int seconds);
  Future<bool> canQuickUnlock();
  Future<List<WorkspaceInfo>> enableQuickUnlock(UnlockedWorkspace workspace);
  Future<List<WorkspaceInfo>> disableQuickUnlock(WorkspaceInfo workspace);
  Future<QuickUnlockOutcome> quickUnlock(List<WorkspaceInfo> workspaces);
}

class WorkspaceRegistryException implements Exception {
  const WorkspaceRegistryException();
}

class NativeVaultService implements SecurityVaultService {
  NativeVaultService._(
    this._registryFile,
    this._vaultDirectory,
    this.platformSecurity,
    this._newWorkspaceId,
  );

  NativeVaultService.forTesting({
    required File registryFile,
    required Directory vaultDirectory,
    required PlatformSecurityService platformSecurity,
    required String Function() newWorkspaceId,
  }) : this._(registryFile, vaultDirectory, platformSecurity, newWorkspaceId);

  final File _registryFile;
  final Directory _vaultDirectory;
  @override
  final PlatformSecurityService platformSecurity;
  final String Function() _newWorkspaceId;
  List<WorkspaceInfo>? _cachedWorkspaces;
  @override
  int autoLockSeconds = 300;

  static Future<NativeVaultService> create({
    PlatformSecurityService? platformSecurity,
  }) async {
    final support = await getApplicationSupportDirectory();
    final vaultDirectory = Directory(
      '${support.path}${Platform.pathSeparator}vaults',
    );
    await vaultDirectory.create(recursive: true);
    return NativeVaultService._(
      File('${support.path}${Platform.pathSeparator}workspaces.json'),
      vaultDirectory,
      platformSecurity ?? MethodChannelSecurityService(),
      native.generateWorkspaceId,
    );
  }

  @override
  Future<List<WorkspaceInfo>> loadWorkspaces() async {
    if (_cachedWorkspaces case final cached?) return List.of(cached);
    if (!await _registryFile.exists()) return [];
    try {
      final source = await _registryFile.readAsString();
      final decoded = jsonDecode(source);
      late List<WorkspaceInfo> workspaces;
      if (decoded is List<Object?>) {
        workspaces = decoded
            .map((value) {
              final legacy = WorkspaceInfo.fromJson(
                value! as Map<String, Object?>,
              );
              return WorkspaceInfo(
                id: _newWorkspaceId(),
                name: legacy.name,
                path: legacy.path,
              );
            })
            .toList(growable: false);
        await _registryFile.copy('${_registryFile.path}.bak');
        await _writeRegistry(workspaces);
      } else {
        final root = decoded as Map<String, Object?>;
        if (root['version'] != 1) throw const FormatException();
        autoLockSeconds = root['autoLockSeconds']! as int;
        if (!const [0, 30, 60, 300, 900].contains(autoLockSeconds)) {
          throw const FormatException();
        }
        workspaces = (root['workspaces']! as List<Object?>)
            .map((value) {
              return WorkspaceInfo.fromJson(value! as Map<String, Object?>);
            })
            .toList(growable: false);
      }
      if (workspaces.any((item) => item.quickUnlockEnabled) &&
          !await platformSecurity.hasKeyring()) {
        workspaces = workspaces
            .map((item) => item.copyWith(clear: true))
            .toList();
        await _writeRegistry(workspaces);
      }
      _cachedWorkspaces = workspaces;
      return List.of(workspaces);
    } on Object {
      throw const WorkspaceRegistryException();
    }
  }

  @override
  Future<String?> chooseKdbxFile() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: const ['kdbx'],
      allowMultiple: false,
    );
    return result?.files.single.path;
  }

  @override
  Future<UnlockedWorkspace> createWorkspace(
    String name,
    String password,
  ) async {
    final id = _newWorkspaceId();
    final path = '${_vaultDirectory.path}${Platform.pathSeparator}$id.kdbx';
    final handle = await native.createVault(
      path: path,
      name: name,
      masterPassword: password,
    );
    final workspace = WorkspaceInfo(id: id, name: name, path: path);
    await _appendWorkspace(workspace);
    return UnlockedWorkspace(workspace: workspace, handleId: handle.id);
  }

  @override
  Future<UnlockedWorkspace> importWorkspace(
    String name,
    String path,
    String password,
  ) async {
    final id = _newWorkspaceId();
    final internalPath =
        '${_vaultDirectory.path}${Platform.pathSeparator}$id.kdbx';
    final handle = await native.importVault(
      sourcePath: path,
      destinationPath: internalPath,
      name: name,
      masterPassword: password,
    );
    final workspace = WorkspaceInfo(id: id, name: name, path: internalPath);
    await _appendWorkspace(workspace);
    return UnlockedWorkspace(workspace: workspace, handleId: handle.id);
  }

  @override
  Future<BigInt> unlock(WorkspaceInfo workspace, String password) async {
    final handle = await native.openVault(
      path: workspace.path,
      masterPassword: password,
    );
    return handle.id;
  }

  @override
  Future<void> lockAll() async => native.lockAllVaults();

  @override
  Future<List<VaultEntryItem>> listEntries(BigInt handleId) async => native
      .listEntries(handleId: handleId)
      .map(
        (entry) => VaultEntryItem(
          id: entry.id,
          type: _fromNativeKind(entry.kind),
          title: entry.title,
          username: entry.username,
          url: entry.url,
          hasPassword: entry.hasPassword,
          hasOtp: entry.hasOtp,
          tags: entry.tags,
        ),
      )
      .toList(growable: false);

  @override
  Future<void> createEntry(BigInt handleId, VaultEntryDraft draft) async {
    await native.createEntry(handleId: handleId, input: _toNativeInput(draft));
  }

  @override
  Future<void> updateEntry(
    BigInt handleId,
    String entryId,
    VaultEntryDraft draft,
  ) async {
    await native.updateEntry(
      handleId: handleId,
      entryId: entryId,
      input: _toNativeInput(draft),
    );
  }

  @override
  Future<void> deleteEntry(BigInt handleId, String entryId) =>
      native.deleteEntry(handleId: handleId, entryId: entryId);

  @override
  Future<String> revealPassword(BigInt handleId, String entryId) async =>
      native.revealEntryField(
        handleId: handleId,
        entryId: entryId,
        field: native.SensitiveField.password,
      );

  @override
  Future<String> revealNotes(BigInt handleId, String entryId) async =>
      native.revealEntryField(
        handleId: handleId,
        entryId: entryId,
        field: native.SensitiveField.notes,
      );

  @override
  Future<OtpValue> currentOtp(
    BigInt handleId,
    String entryId,
    DateTime now,
  ) async {
    final value = native.currentEntryOtp(
      handleId: handleId,
      entryId: entryId,
      unixSeconds: now.millisecondsSinceEpoch ~/ 1000,
    );
    return OtpValue(
      code: value.code,
      validForSeconds: value.validForSeconds?.toInt(),
    );
  }

  @override
  Future<void> importOtp(BigInt handleId, String uri) async {
    await native.importOtpToVault(
      handleId: handleId,
      uri: uri,
      modifiedAtUnixMs: DateTime.now().millisecondsSinceEpoch,
    );
  }

  @override
  Future<SyncSummary> syncWebDav(
    BigInt handleId,
    String workspaceId,
    WebDavSettings settings,
  ) async {
    final backupDirectory = Directory(
      '${_vaultDirectory.path}${Platform.pathSeparator}backups'
      '${Platform.pathSeparator}$workspaceId',
    );
    final result = await native.syncWebdav(
      handleId: handleId,
      endpoint: settings.endpoint,
      username: settings.username,
      password: settings.password,
      allowInsecureHttp: settings.allowInsecureHttp,
      backupDirectory: backupDirectory.path,
    );
    return SyncSummary(attempts: result.attempts, merged: result.merged);
  }

  @override
  Future<void> setAutoLockSeconds(int seconds) async {
    if (!const [0, 30, 60, 300, 900].contains(seconds)) {
      throw ArgumentError.value(seconds);
    }
    autoLockSeconds = seconds;
    await _writeRegistry(await loadWorkspaces());
  }

  @override
  Future<bool> canQuickUnlock() => platformSecurity.canAuthenticateStrong();

  @override
  Future<List<WorkspaceInfo>> enableQuickUnlock(
    UnlockedWorkspace workspace,
  ) async {
    final workspaces = await loadWorkspaces();
    Uint8List? oldKeyring;
    native.QuickUnlockEnrollment? enrollment;
    try {
      if (workspaces.any((item) => item.quickUnlockEnabled)) {
        oldKeyring = await platformSecurity.unsealKeyring();
      }
      enrollment = await native.prepareQuickUnlockEnrollment(
        handleId: workspace.handleId,
        workspaceId: workspace.workspace.id,
        existingKeyring: oldKeyring,
      );
      await platformSecurity.sealKeyring(enrollment.updatedKeyring);
      final updated = workspaces
          .map((item) {
            return item.id == workspace.workspace.id
                ? item.copyWith(
                    quickUnlockEnvelope: Uint8List.fromList(
                      enrollment!.envelope,
                    ),
                  )
                : item;
          })
          .toList(growable: false);
      await _writeRegistry(updated);
      return updated;
    } on PlatformSecurityFailure catch (error) {
      await _handleInvalidation(error);
      rethrow;
    } finally {
      if (oldKeyring != null) eraseBytes(oldKeyring);
      if (enrollment != null) eraseBytes(enrollment.updatedKeyring);
    }
  }

  @override
  Future<List<WorkspaceInfo>> disableQuickUnlock(
    WorkspaceInfo workspace,
  ) async {
    final workspaces = await loadWorkspaces();
    final enabled = workspaces.where((item) => item.quickUnlockEnabled).length;
    if (!workspace.quickUnlockEnabled) return workspaces;
    if (enabled == 1) {
      await platformSecurity.clearKeyring();
    } else {
      Uint8List? oldKeyring;
      Uint8List? updatedKeyring;
      try {
        oldKeyring = await platformSecurity.unsealKeyring();
        updatedKeyring = await native.removeQuickUnlockMaterial(
          workspaceId: workspace.id,
          keyring: oldKeyring,
        );
        await platformSecurity.sealKeyring(updatedKeyring);
      } on PlatformSecurityFailure catch (error) {
        await _handleInvalidation(error);
        rethrow;
      } finally {
        if (oldKeyring != null) eraseBytes(oldKeyring);
        if (updatedKeyring != null) eraseBytes(updatedKeyring);
      }
    }
    final updated = workspaces
        .map((item) {
          return item.id == workspace.id ? item.copyWith(clear: true) : item;
        })
        .toList(growable: false);
    await _writeRegistry(updated);
    return updated;
  }

  @override
  Future<QuickUnlockOutcome> quickUnlock(List<WorkspaceInfo> workspaces) async {
    final selected = workspaces
        .where((item) => item.quickUnlockEnabled)
        .toList();
    if (selected.isEmpty) {
      return const QuickUnlockOutcome(opened: [], failedIds: []);
    }
    Uint8List? keyring;
    try {
      keyring = await platformSecurity.unsealKeyring();
      final result = await native.openVaultsWithQuickUnlock(
        requests: selected
            .map((item) {
              return native.QuickUnlockRequest(
                workspaceId: item.id,
                path: item.path,
                envelope: item.quickUnlockEnvelope!,
              );
            })
            .toList(growable: false),
        keyring: keyring,
      );
      final byId = {for (final item in selected) item.id: item};
      return QuickUnlockOutcome(
        opened: result.opened
            .map((value) {
              return UnlockedWorkspace(
                workspace: byId[value.workspaceId]!,
                handleId: value.handleId,
              );
            })
            .toList(growable: false),
        failedIds: result.failedWorkspaceIds,
      );
    } on PlatformSecurityFailure catch (error) {
      await _handleInvalidation(error);
      rethrow;
    } finally {
      if (keyring != null) eraseBytes(keyring);
    }
  }

  Future<void> _handleInvalidation(PlatformSecurityFailure error) async {
    if (!error.isKeyInvalidated) return;
    await platformSecurity.clearKeyring();
    final workspaces = (await loadWorkspaces())
        .map((item) => item.copyWith(clear: true))
        .toList(growable: false);
    await _writeRegistry(workspaces);
  }

  Future<void> _appendWorkspace(WorkspaceInfo workspace) async {
    final workspaces = await loadWorkspaces();
    if (workspaces.any((item) => item.path == workspace.path)) return;
    await _writeRegistry([...workspaces, workspace]);
  }

  Future<void> _writeRegistry(List<WorkspaceInfo> workspaces) async {
    final temporary = File('${_registryFile.path}.tmp');
    await temporary.writeAsString(
      jsonEncode({
        'version': 1,
        'autoLockSeconds': autoLockSeconds,
        'workspaces': workspaces.map((item) => item.toJson()).toList(),
      }),
      flush: true,
    );
    await temporary.rename(_registryFile.path);
    _cachedWorkspaces = List.of(workspaces);
  }
}

native.VaultEntryInput _toNativeInput(VaultEntryDraft draft) =>
    native.VaultEntryInput(
      kind: switch (draft.type) {
        EntryType.login => native.VaultEntryKind.login,
        EntryType.otp => native.VaultEntryKind.otp,
        EntryType.recoveryCodes => native.VaultEntryKind.recoveryCodes,
        EntryType.secureNote => native.VaultEntryKind.secureNote,
      },
      title: draft.title,
      username: draft.username,
      password: draft.password,
      url: draft.url,
      notes: draft.notes,
      tags: draft.tags,
      otpUri: draft.otpUri,
      preserveExistingOtp: draft.preserveExistingOtp,
      modifiedAtUnixMs: DateTime.now().millisecondsSinceEpoch,
    );

EntryType _fromNativeKind(native.VaultEntryKind kind) => switch (kind) {
  native.VaultEntryKind.login => EntryType.login,
  native.VaultEntryKind.otp => EntryType.otp,
  native.VaultEntryKind.recoveryCodes => EntryType.recoveryCodes,
  native.VaultEntryKind.secureNote => EntryType.secureNote,
};
