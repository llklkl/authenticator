import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:authenticator_vault/src/rust/api/simple.dart' as native;
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';

enum EntryType { login, otp, recoveryCodes, secureNote }

class WorkspaceInfo {
  const WorkspaceInfo({
    required this.id,
    required this.name,
    required this.path,
  });

  final String id;
  final String name;
  final String path;

  Map<String, Object> toJson() => {'id': id, 'name': name, 'path': path};

  factory WorkspaceInfo.fromJson(Map<String, Object?> json) => WorkspaceInfo(
    id: json['id']! as String,
    name: json['name']! as String,
    path: json['path']! as String,
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

class NativeVaultService implements VaultService {
  NativeVaultService._(this._registryFile, this._vaultDirectory);

  final File _registryFile;
  final Directory _vaultDirectory;

  static Future<NativeVaultService> create() async {
    final support = await getApplicationSupportDirectory();
    final vaultDirectory = Directory(
      '${support.path}${Platform.pathSeparator}vaults',
    );
    await vaultDirectory.create(recursive: true);
    return NativeVaultService._(
      File('${support.path}${Platform.pathSeparator}workspaces.json'),
      vaultDirectory,
    );
  }

  @override
  Future<List<WorkspaceInfo>> loadWorkspaces() async {
    if (!await _registryFile.exists()) return [];
    try {
      final decoded =
          jsonDecode(await _registryFile.readAsString()) as List<Object?>;
      return decoded
          .map(
            (value) => WorkspaceInfo.fromJson(value! as Map<String, Object?>),
          )
          .toList(growable: false);
    } on Object {
      return [];
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
    final random = Random.secure().nextInt(1 << 32).toRadixString(16);
    final id = '${DateTime.now().microsecondsSinceEpoch}-$random';
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
    final handle = await native.openVault(path: path, masterPassword: password);
    final id = 'import-${DateTime.now().microsecondsSinceEpoch}';
    final workspace = WorkspaceInfo(id: id, name: name, path: path);
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

  Future<void> _appendWorkspace(WorkspaceInfo workspace) async {
    final workspaces = await loadWorkspaces();
    if (workspaces.any((item) => item.path == workspace.path)) return;
    await _writeRegistry([...workspaces, workspace]);
  }

  Future<void> _writeRegistry(List<WorkspaceInfo> workspaces) async {
    final temporary = File('${_registryFile.path}.tmp');
    await temporary.writeAsString(
      jsonEncode(workspaces.map((item) => item.toJson()).toList()),
      flush: true,
    );
    await temporary.rename(_registryFile.path);
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
