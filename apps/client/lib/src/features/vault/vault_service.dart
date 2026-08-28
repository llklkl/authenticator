import 'dart:convert';
import 'dart:io';

import 'package:authenticator_vault/src/features/security/platform_security_service.dart';
import 'package:authenticator_vault/src/rust/api/simple.dart' as native;
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path_provider/path_provider.dart';

enum EntryType { login, otp, recoveryCodes, secureNote }

enum AppThemePreference { system, light, dark }

enum AppLanguage { zhHans, english }

class AppPreferences {
  const AppPreferences({
    this.theme = AppThemePreference.system,
    this.language = AppLanguage.zhHans,
    this.passwordSymbols = '!@#\$%^&*()-_=+[]{};:,.?',
  });

  final AppThemePreference theme;
  final AppLanguage language;
  final String passwordSymbols;

  AppPreferences copyWith({
    AppThemePreference? theme,
    AppLanguage? language,
    String? passwordSymbols,
  }) => AppPreferences(
    theme: theme ?? this.theme,
    language: language ?? this.language,
    passwordSymbols: passwordSymbols ?? this.passwordSymbols,
  );
}

String suggestWorkspaceName(String path) {
  final fileName = path.replaceAll('\\', '/').split('/').last.trim();
  final withoutExtension = fileName.replaceFirst(
    RegExp(r'\.kdbx$', caseSensitive: false),
    '',
  );
  return withoutExtension.isEmpty ? 'Imported Workspace' : withoutExtension;
}

class WorkspaceInfo {
  const WorkspaceInfo({
    required this.id,
    required this.name,
    required this.path,
    this.quickUnlockEnvelope,
    this.sync = const WorkspaceSyncSettings(),
  });

  final String id;
  final String name;
  final String path;
  final Uint8List? quickUnlockEnvelope;
  final WorkspaceSyncSettings sync;

  bool get quickUnlockEnabled => quickUnlockEnvelope != null;

  Map<String, Object> toJson() => {
    'id': id,
    'name': name,
    'path': path,
    if (quickUnlockEnvelope case final envelope?)
      'quickUnlockEnvelope': base64Encode(envelope),
    'sync': sync.toJson(),
  };

  factory WorkspaceInfo.fromJson(Map<String, Object?> json) => WorkspaceInfo(
    id: json['id']! as String,
    name: json['name']! as String,
    path: json['path']! as String,
    quickUnlockEnvelope: switch (json['quickUnlockEnvelope']) {
      final String value => Uint8List.fromList(base64Decode(value)),
      _ => null,
    },
    sync: switch (json['sync']) {
      final Map<String, Object?> value => WorkspaceSyncSettings.fromJson(value),
      _ => const WorkspaceSyncSettings(),
    },
  );

  WorkspaceInfo copyWith({
    Uint8List? quickUnlockEnvelope,
    bool clear = false,
    WorkspaceSyncSettings? sync,
  }) => WorkspaceInfo(
    id: id,
    name: name,
    path: path,
    quickUnlockEnvelope: clear
        ? null
        : quickUnlockEnvelope ?? this.quickUnlockEnvelope,
    sync: sync ?? this.sync,
  );
}

class WorkspaceSyncSettings {
  const WorkspaceSyncSettings({
    this.endpoint = '',
    this.username = '',
    this.allowInsecureHttp = false,
    this.autoSync = true,
    this.nonMeteredOnly = false,
    this.passwordStored = false,
  });

  final String endpoint;
  final String username;
  final bool allowInsecureHttp;
  final bool autoSync;
  final bool nonMeteredOnly;
  final bool passwordStored;

  bool get configured => endpoint.trim().isNotEmpty;

  Map<String, Object> toJson() => {
    'endpoint': endpoint,
    'username': username,
    'allowInsecureHttp': allowInsecureHttp,
    'autoSync': autoSync,
    'nonMeteredOnly': nonMeteredOnly,
    'passwordStored': passwordStored,
  };

  factory WorkspaceSyncSettings.fromJson(Map<String, Object?> json) =>
      WorkspaceSyncSettings(
        endpoint: json['endpoint'] as String? ?? '',
        username: json['username'] as String? ?? '',
        allowInsecureHttp: json['allowInsecureHttp'] as bool? ?? false,
        autoSync: json['autoSync'] as bool? ?? true,
        nonMeteredOnly: json['nonMeteredOnly'] as bool? ?? false,
        passwordStored: json['passwordStored'] as bool? ?? false,
      );
}

enum VaultIconType { none, builtIn, custom }

class VaultIconItem {
  const VaultIconItem({required this.type, this.builtInId, this.customId});
  final VaultIconType type;
  final int? builtInId;
  final String? customId;
}

class VaultAttachmentItem {
  const VaultAttachmentItem({
    required this.name,
    required this.size,
    required this.isProtected,
  });
  final String name;
  final int size;
  final bool isProtected;
}

class UnlockedWorkspace {
  const UnlockedWorkspace({
    required this.workspace,
    required this.handleId,
    this.writable = true,
    this.format = 'KDBX 4.1',
  });

  final WorkspaceInfo workspace;
  final BigInt handleId;
  final bool writable;
  final String format;
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
    this.modifiedAtUnixMs = 0,
    this.groupId = '',
    this.isInRecycleBin = false,
    this.icon = const VaultIconItem(type: VaultIconType.none),
    this.attachments = const [],
    this.isFavorite = false,
  });

  final String id;
  final EntryType type;
  final String title;
  final String username;
  final String url;
  final bool hasPassword;
  final bool hasOtp;
  final List<String> tags;
  final int modifiedAtUnixMs;
  final String groupId;
  final bool isInRecycleBin;
  final VaultIconItem icon;
  final List<VaultAttachmentItem> attachments;
  final bool isFavorite;
}

class VaultGroupItem {
  const VaultGroupItem({
    required this.id,
    required this.parentId,
    required this.name,
    required this.isRoot,
    required this.isRecycleBin,
    this.icon = const VaultIconItem(type: VaultIconType.none),
  });

  final String id;
  final String? parentId;
  final String name;
  final bool isRoot;
  final bool isRecycleBin;
  final VaultIconItem icon;
}

enum PasswordHealthRisk { empty, duplicate, weak, stale, missingOtp }

class PasswordHealthFinding {
  const PasswordHealthFinding({required this.entryId, required this.risks});
  final String entryId;
  final List<PasswordHealthRisk> risks;
}

class GeneratedPassword {
  const GeneratedPassword({required this.value, required this.entropyBits});
  final String value;
  final int entropyBits;
}

class VaultContent {
  const VaultContent({
    required this.rootGroupId,
    required this.recycleBinEnabled,
    required this.recycleBinId,
    required this.groups,
    required this.entries,
  });

  final String rootGroupId;
  final bool recycleBinEnabled;
  final String? recycleBinId;
  final List<VaultGroupItem> groups;
  final List<VaultEntryItem> entries;
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
  const OtpValue({
    required this.code,
    this.validForSeconds,
    this.periodSeconds,
  });

  final String code;
  final int? validForSeconds;
  final int? periodSeconds;
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

enum SyncAction { createdRemote, uploaded, downloaded, merged, unchanged }

class SyncSummary {
  const SyncSummary({
    required this.attempts,
    required this.merged,
    this.action = SyncAction.unchanged,
    this.autoMergedObjects = 0,
    this.createdConflicts = 0,
    this.pendingConflicts = 0,
    this.baselineRebuilt = false,
  });
  final int attempts;
  final bool merged;
  final SyncAction action;
  final int autoMergedObjects;
  final int createdConflicts;
  final int pendingConflicts;
  final bool baselineRebuilt;
}

enum SyncConflictChoice { primary, alternate }

enum RestoreSyncDecision { merge, replaceRemote }

class SyncConflictItem {
  const SyncConflictItem({
    required this.id,
    required this.title,
    required this.fields,
  });
  final String id;
  final String title;
  final List<String> fields;
}

class SyncBackupItem {
  const SyncBackupItem({
    required this.id,
    required this.createdAt,
    required this.encryptedSize,
    required this.origin,
  });
  final String id;
  final DateTime createdAt;
  final int encryptedSize;
  final String origin;
}

class SyncDiagnosticItem {
  const SyncDiagnosticItem({
    required this.timestamp,
    required this.outcome,
    required this.errorCode,
    required this.attempts,
    required this.durationMs,
    required this.pendingConflicts,
  });
  final DateTime timestamp;
  final String outcome;
  final String? errorCode;
  final int attempts;
  final int durationMs;
  final int pendingConflicts;
}

class SyncStateItem {
  const SyncStateItem({
    required this.pendingConflicts,
    required this.restorePending,
    required this.attachmentConflict,
  });
  final int pendingConflicts;
  final bool restorePending;
  final bool attachmentConflict;
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

abstract interface class StructuredVaultService implements VaultService {
  Future<VaultContent> content(BigInt handleId);
  Future<void> createEntryInGroup(
    BigInt handleId,
    String groupId,
    VaultEntryDraft draft,
  );
  Future<String> createGroup(
    BigInt handleId,
    String parentId,
    String name, {
    int? iconId,
  });
  Future<void> renameGroup(BigInt handleId, String groupId, String name);
  Future<void> moveGroup(BigInt handleId, String groupId, String destinationId);
  Future<void> moveEntry(BigInt handleId, String entryId, String destinationId);
  Future<String> enableRecycleBin(BigInt handleId);
  Future<void> trashEntry(BigInt handleId, String entryId);
  Future<void> trashGroup(BigInt handleId, String groupId);
  Future<void> restoreEntry(BigInt handleId, String entryId);
  Future<void> restoreGroup(BigInt handleId, String groupId);
  Future<void> permanentlyDeleteGroup(BigInt handleId, String groupId);
  Future<void> emptyRecycleBin(BigInt handleId);
}

abstract interface class ProductivityVaultService
    implements StructuredVaultService, SecurityVaultService {
  int get stalePasswordDays;
  ValueListenable<AppPreferences> get preferences;
  Future<void> setThemePreference(AppThemePreference theme);
  Future<void> setLanguage(AppLanguage language);
  Future<String> setPasswordSymbols(String symbols);
  Future<void> setStalePasswordDays(int days);
  Future<void> setGroupIcon(BigInt handleId, String groupId, int? iconId);
  Future<Uint8List> loadCustomIcon(BigInt handleId, String customIconId);
  Future<void> setFavorite(BigInt handleId, String entryId, bool favorite);
  Future<String?> chooseAttachmentFile();
  Future<String?> chooseAttachmentExportPath(String suggestedName);
  Future<void> addAttachment(
    BigInt handleId,
    String entryId,
    String name,
    String sourcePath, {
    bool replace = false,
  });
  Future<void> exportAttachment(
    BigInt handleId,
    String entryId,
    String name,
    String destinationPath, {
    bool overwrite = false,
  });
  Future<void> renameAttachment(
    BigInt handleId,
    String entryId,
    String oldName,
    String newName,
  );
  Future<void> removeAttachment(BigInt handleId, String entryId, String name);
  Future<List<PasswordHealthFinding>> passwordHealth(BigInt handleId);
  Future<GeneratedPassword> generateRandomPassword({
    int length = 20,
    bool lowercase = true,
    bool uppercase = true,
    bool digits = true,
    bool symbols = true,
    String? symbolCharacters,
    bool excludeAmbiguous = true,
  });
  Future<GeneratedPassword> generatePassphrase({
    int wordCount = 6,
    String separator = '-',
    bool capitalize = false,
    bool includeNumber = false,
  });
  Future<List<WorkspaceInfo>> saveWorkspaceSync(
    WorkspaceInfo workspace,
    WorkspaceSyncSettings settings, {
    String? password,
  });
  Future<SyncSummary> syncConfiguredWorkspace(
    BigInt handleId,
    WorkspaceInfo workspace, {
    String? passwordOverride,
  });
  bool isVaultWritable(BigInt handleId);
  String vaultFormat(BigInt handleId);
  Future<List<SyncConflictItem>> listSyncConflicts(BigInt handleId);
  Future<void> resolveSyncConflict(
    BigInt handleId,
    String conflictId,
    SyncConflictChoice defaultChoice, {
    Map<String, SyncConflictChoice> fieldChoices = const {},
  });
  Future<List<SyncBackupItem>> listSyncBackups(
    BigInt handleId,
    String workspaceId,
  );
  Future<void> restoreSyncBackup(
    BigInt handleId,
    String workspaceId,
    String backupId,
  );
  Future<SyncSummary> completeRestoreSync(
    BigInt handleId,
    WorkspaceInfo workspace,
    RestoreSyncDecision decision, {
    String? passwordOverride,
  });
  Future<List<SyncDiagnosticItem>> listSyncDiagnostics(String workspaceId);
  Future<SyncStateItem> syncState(String workspaceId);
  Future<String?> chooseDiagnosticsExportPath();
  Future<void> exportSyncDiagnostics(String workspaceId, String path);
  Future<void> clearSyncDiagnostics(String workspaceId);
}

class NativeVaultService implements ProductivityVaultService {
  NativeVaultService._(
    this._registryFile,
    this._vaultDirectory,
    this.platformSecurity,
    this._newWorkspaceId,
    this._secureStorage,
    this._normalizePasswordSymbols,
  );

  final Map<BigInt, ({bool writable, String format})> _vaultFormats = {};

  NativeVaultService.forTesting({
    required File registryFile,
    required Directory vaultDirectory,
    required PlatformSecurityService platformSecurity,
    required String Function() newWorkspaceId,
    FlutterSecureStorage? secureStorage,
    String Function(String)? normalizePasswordSymbols,
  }) : this._(
         registryFile,
         vaultDirectory,
         platformSecurity,
         newWorkspaceId,
         secureStorage ?? const FlutterSecureStorage(),
         normalizePasswordSymbols ??
             ((value) => native.normalizePasswordSymbols(value: value)),
       );

  final File _registryFile;
  final Directory _vaultDirectory;
  final String Function(String) _normalizePasswordSymbols;
  @override
  final PlatformSecurityService platformSecurity;
  final String Function() _newWorkspaceId;
  final FlutterSecureStorage _secureStorage;
  List<WorkspaceInfo>? _cachedWorkspaces;
  @override
  int autoLockSeconds = 300;
  @override
  int stalePasswordDays = 180;
  @override
  final ValueNotifier<AppPreferences> preferences = ValueNotifier(
    const AppPreferences(),
  );

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
      const FlutterSecureStorage(),
      (value) => native.normalizePasswordSymbols(value: value),
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
        final version = root['version'];
        if (version != 1 && version != 2 && version != 3) {
          throw const FormatException();
        }
        autoLockSeconds = root['autoLockSeconds']! as int;
        if (!const [0, 30, 60, 300, 900].contains(autoLockSeconds)) {
          throw const FormatException();
        }
        workspaces = (root['workspaces']! as List<Object?>)
            .map((value) {
              return WorkspaceInfo.fromJson(value! as Map<String, Object?>);
            })
            .toList(growable: false);
        if (version == 2 || version == 3) {
          stalePasswordDays = root['stalePasswordDays'] as int? ?? 180;
          if (!const [0, 90, 180, 365].contains(stalePasswordDays)) {
            throw const FormatException();
          }
        }
        if (version == 3) {
          preferences.value = AppPreferences(
            theme: _themePreferenceFromJson(root['themeMode']! as String),
            language: _languageFromJson(root['locale']! as String),
            passwordSymbols: _normalizePasswordSymbols(
              root['passwordSymbols']! as String,
            ),
          );
        } else {
          await _registryFile.copy('${_registryFile.path}.bak');
          await _writeRegistry(workspaces);
        }
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
    final result = await FilePicker.pickFile(
      type: FileType.custom,
      allowedExtensions: const ['kdbx'],
    );
    return result?.path;
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
    _rememberHandle(handle);
    return UnlockedWorkspace(
      workspace: workspace,
      handleId: handle.id,
      writable: handle.writable,
      format: _formatName(handle.format),
    );
  }

  @override
  Future<UnlockedWorkspace> importWorkspace(
    String name,
    String path,
    String password,
  ) async {
    final id = _newWorkspaceId();
    final displayName = name.trim().isEmpty
        ? suggestWorkspaceName(path)
        : name.trim();
    final internalPath =
        '${_vaultDirectory.path}${Platform.pathSeparator}$id.kdbx';
    final handle = await native.importVault(
      sourcePath: path,
      destinationPath: internalPath,
      name: displayName,
      masterPassword: password,
    );
    final workspace = WorkspaceInfo(
      id: id,
      name: displayName,
      path: internalPath,
    );
    await _appendWorkspace(workspace);
    _rememberHandle(handle);
    return UnlockedWorkspace(
      workspace: workspace,
      handleId: handle.id,
      writable: handle.writable,
      format: _formatName(handle.format),
    );
  }

  @override
  Future<BigInt> unlock(WorkspaceInfo workspace, String password) async {
    final handle = await native.openVault(
      path: workspace.path,
      masterPassword: password,
    );
    _rememberHandle(handle);
    return handle.id;
  }

  @override
  Future<void> lockAll() async {
    native.lockAllVaults();
    _vaultFormats.clear();
  }

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
          modifiedAtUnixMs: entry.modifiedAtUnixMs,
          groupId: entry.groupId,
          isInRecycleBin: entry.isInRecycleBin,
          icon: _fromNativeIcon(entry.icon),
          attachments: entry.attachments.map(_fromNativeAttachment).toList(),
          isFavorite: entry.isFavorite,
        ),
      )
      .toList(growable: false);

  @override
  Future<VaultContent> content(BigInt handleId) async {
    final value = native.vaultContent(handleId: handleId);
    return VaultContent(
      rootGroupId: value.rootGroupId,
      recycleBinEnabled: value.recycleBinEnabled,
      recycleBinId: value.recycleBinId,
      groups: value.groups
          .map(
            (group) => VaultGroupItem(
              id: group.id,
              parentId: group.parentId,
              name: group.name,
              isRoot: group.isRoot,
              isRecycleBin: group.isRecycleBin,
              icon: _fromNativeIcon(group.icon),
            ),
          )
          .toList(growable: false),
      entries: value.entries
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
              modifiedAtUnixMs: entry.modifiedAtUnixMs,
              groupId: entry.groupId,
              isInRecycleBin: entry.isInRecycleBin,
              icon: _fromNativeIcon(entry.icon),
              attachments: entry.attachments
                  .map(_fromNativeAttachment)
                  .toList(),
              isFavorite: entry.isFavorite,
            ),
          )
          .toList(growable: false),
    );
  }

  @override
  Future<void> createEntry(BigInt handleId, VaultEntryDraft draft) async {
    await native.createEntry(handleId: handleId, input: _toNativeInput(draft));
  }

  @override
  Future<void> createEntryInGroup(
    BigInt handleId,
    String groupId,
    VaultEntryDraft draft,
  ) async {
    await native.createEntryInGroup(
      handleId: handleId,
      groupId: groupId,
      input: _toNativeInput(draft),
    );
  }

  @override
  Future<String> createGroup(
    BigInt handleId,
    String parentId,
    String name, {
    int? iconId,
  }) => native.createGroupWithIcon(
    handleId: handleId,
    parentId: parentId,
    name: name,
    builtInIconId: iconId,
  );

  @override
  Future<void> renameGroup(BigInt handleId, String groupId, String name) =>
      native.renameGroup(handleId: handleId, groupId: groupId, name: name);

  @override
  Future<void> moveGroup(
    BigInt handleId,
    String groupId,
    String destinationId,
  ) => native.moveGroup(
    handleId: handleId,
    groupId: groupId,
    destinationId: destinationId,
  );

  @override
  Future<void> moveEntry(
    BigInt handleId,
    String entryId,
    String destinationId,
  ) => native.moveEntry(
    handleId: handleId,
    entryId: entryId,
    destinationId: destinationId,
  );

  @override
  Future<String> enableRecycleBin(BigInt handleId) =>
      native.enableRecycleBin(handleId: handleId);

  @override
  Future<void> trashEntry(BigInt handleId, String entryId) =>
      native.trashEntry(handleId: handleId, entryId: entryId);

  @override
  Future<void> trashGroup(BigInt handleId, String groupId) =>
      native.trashGroup(handleId: handleId, groupId: groupId);

  @override
  Future<void> restoreEntry(BigInt handleId, String entryId) =>
      native.restoreEntry(handleId: handleId, entryId: entryId);

  @override
  Future<void> restoreGroup(BigInt handleId, String groupId) =>
      native.restoreGroup(handleId: handleId, groupId: groupId);

  @override
  Future<void> permanentlyDeleteGroup(BigInt handleId, String groupId) =>
      native.permanentlyDeleteGroup(handleId: handleId, groupId: groupId);

  @override
  Future<void> emptyRecycleBin(BigInt handleId) =>
      native.emptyRecycleBin(handleId: handleId);

  @override
  Future<void> setGroupIcon(BigInt handleId, String groupId, int? iconId) =>
      native.setGroupIcon(
        handleId: handleId,
        groupId: groupId,
        builtInIconId: iconId,
      );

  @override
  Future<Uint8List> loadCustomIcon(
    BigInt handleId,
    String customIconId,
  ) async =>
      native.loadCustomIcon(handleId: handleId, customIconId: customIconId);

  @override
  Future<void> setFavorite(BigInt handleId, String entryId, bool favorite) =>
      native.setEntryFavorite(
        handleId: handleId,
        entryId: entryId,
        favorite: favorite,
      );

  @override
  Future<String?> chooseAttachmentFile() async {
    final result = await FilePicker.pickFile();
    return result?.path;
  }

  @override
  Future<String?> chooseAttachmentExportPath(String suggestedName) async {
    final destination = await FilePicker.saveFile(
      fileName: suggestedName,
      bytes: Uint8List(0),
    );
    if (destination == null) return null;
    if (destination.scheme != 'file') {
      throw UnsupportedError('The selected destination is not a local file.');
    }
    return destination.toFilePath();
  }

  @override
  Future<void> addAttachment(
    BigInt handleId,
    String entryId,
    String name,
    String sourcePath, {
    bool replace = false,
  }) => native.addEntryAttachment(
    handleId: handleId,
    entryId: entryId,
    attachmentName: name,
    sourcePath: sourcePath,
    replace: replace,
  );

  @override
  Future<void> exportAttachment(
    BigInt handleId,
    String entryId,
    String name,
    String destinationPath, {
    bool overwrite = false,
  }) => native.exportEntryAttachment(
    handleId: handleId,
    entryId: entryId,
    attachmentName: name,
    destinationPath: destinationPath,
    overwrite: overwrite,
  );

  @override
  Future<void> renameAttachment(
    BigInt handleId,
    String entryId,
    String oldName,
    String newName,
  ) => native.renameEntryAttachment(
    handleId: handleId,
    entryId: entryId,
    oldName: oldName,
    newName: newName,
  );

  @override
  Future<void> removeAttachment(BigInt handleId, String entryId, String name) =>
      native.removeEntryAttachment(
        handleId: handleId,
        entryId: entryId,
        attachmentName: name,
      );

  @override
  Future<List<PasswordHealthFinding>> passwordHealth(BigInt handleId) async {
    final report = native.auditPasswordHealth(
      handleId: handleId,
      staleAfterDays: stalePasswordDays == 0 ? null : stalePasswordDays,
      nowUnixMs: DateTime.now().millisecondsSinceEpoch,
    );
    return report.findings
        .map(
          (finding) => PasswordHealthFinding(
            entryId: finding.entryId,
            risks: finding.risks.map(_fromNativeHealthRisk).toList(),
          ),
        )
        .toList(growable: false);
  }

  @override
  Future<GeneratedPassword> generateRandomPassword({
    int length = 20,
    bool lowercase = true,
    bool uppercase = true,
    bool digits = true,
    bool symbols = true,
    String? symbolCharacters,
    bool excludeAmbiguous = true,
  }) async {
    final value = native.generateRandomPassword(
      length: length,
      lowercase: lowercase,
      uppercase: uppercase,
      digits: digits,
      symbols: symbols,
      symbolCharacters: symbolCharacters ?? preferences.value.passwordSymbols,
      excludeAmbiguous: excludeAmbiguous,
    );
    return GeneratedPassword(
      value: value.value,
      entropyBits: value.entropyBits,
    );
  }

  @override
  Future<GeneratedPassword> generatePassphrase({
    int wordCount = 6,
    String separator = '-',
    bool capitalize = false,
    bool includeNumber = false,
  }) async {
    final value = native.generatePassphrase(
      wordCount: wordCount,
      separator: separator,
      capitalize: capitalize,
      includeNumber: includeNumber,
    );
    return GeneratedPassword(
      value: value.value,
      entropyBits: value.entropyBits,
    );
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
      periodSeconds: value.periodSeconds?.toInt(),
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
    final backupDirectory = _syncDirectory(workspaceId);
    final result = await native.syncWebdav(
      handleId: handleId,
      endpoint: settings.endpoint,
      username: settings.username,
      password: settings.password,
      allowInsecureHttp: settings.allowInsecureHttp,
      backupDirectory: backupDirectory.path,
    );
    return _fromNativeSyncResult(result);
  }

  @override
  bool isVaultWritable(BigInt handleId) =>
      _vaultFormats[handleId]?.writable ?? true;

  @override
  String vaultFormat(BigInt handleId) =>
      _vaultFormats[handleId]?.format ?? 'KDBX 4.1';

  @override
  Future<List<SyncConflictItem>> listSyncConflicts(BigInt handleId) async =>
      (await native.listSyncConflicts(handleId: handleId))
          .map(
            (value) => SyncConflictItem(
              id: value.id,
              title: value.title,
              fields: value.fields.map((field) => field.key).toList(),
            ),
          )
          .toList(growable: false);

  @override
  Future<void> resolveSyncConflict(
    BigInt handleId,
    String conflictId,
    SyncConflictChoice defaultChoice, {
    Map<String, SyncConflictChoice> fieldChoices = const {},
  }) => native.resolveSyncConflict(
    handleId: handleId,
    conflictId: conflictId,
    defaultChoice: _toNativeConflictChoice(defaultChoice),
    fieldChoices: fieldChoices.entries
        .map(
          (entry) => native.ConflictFieldChoiceInput(
            key: entry.key,
            choice: _toNativeConflictChoice(entry.value),
          ),
        )
        .toList(growable: false),
  );

  @override
  Future<List<SyncBackupItem>> listSyncBackups(
    BigInt handleId,
    String workspaceId,
  ) async =>
      (await native.listSyncBackups(
            handleId: handleId,
            stateDirectory: _syncDirectory(workspaceId).path,
          ))
          .map((value) {
            return SyncBackupItem(
              id: value.id,
              createdAt: DateTime.fromMillisecondsSinceEpoch(
                value.createdAtUnixMs,
              ),
              encryptedSize: value.encryptedSize.toInt(),
              origin: value.origin.name,
            );
          })
          .toList(growable: false);

  @override
  Future<void> restoreSyncBackup(
    BigInt handleId,
    String workspaceId,
    String backupId,
  ) => native.restoreSyncBackup(
    handleId: handleId,
    stateDirectory: _syncDirectory(workspaceId).path,
    backupId: backupId,
  );

  @override
  Future<SyncSummary> completeRestoreSync(
    BigInt handleId,
    WorkspaceInfo workspace,
    RestoreSyncDecision decision, {
    String? passwordOverride,
  }) async {
    final config = workspace.sync;
    if (!config.configured) throw StateError('sync is not configured');
    final password = passwordOverride?.isNotEmpty == true
        ? passwordOverride
        : await _secureStorage.read(key: _webDavPasswordKey(workspace.id));
    if (password == null || password.isEmpty) {
      throw StateError('sync credentials are unavailable');
    }
    final result = await native.completeRestoreWebdav(
      handleId: handleId,
      endpoint: config.endpoint,
      username: config.username,
      password: password,
      allowInsecureHttp: config.allowInsecureHttp,
      stateDirectory: _syncDirectory(workspace.id).path,
      decision: switch (decision) {
        RestoreSyncDecision.merge => native.RestoreDecisionView.merge,
        RestoreSyncDecision.replaceRemote =>
          native.RestoreDecisionView.replaceRemote,
      },
    );
    return _fromNativeSyncResult(result);
  }

  @override
  Future<List<SyncDiagnosticItem>> listSyncDiagnostics(
    String workspaceId,
  ) async =>
      (await native.listSyncDiagnostics(
            stateDirectory: _syncDirectory(workspaceId).path,
          ))
          .map((value) {
            return SyncDiagnosticItem(
              timestamp: DateTime.fromMillisecondsSinceEpoch(
                value.timestampUnixMs,
              ),
              outcome: value.outcome,
              errorCode: value.errorCode,
              attempts: value.attempts,
              durationMs: value.durationMs.toInt(),
              pendingConflicts: value.pendingConflicts,
            );
          })
          .toList(growable: false);

  @override
  Future<SyncStateItem> syncState(String workspaceId) async {
    final value = await native.syncState(
      stateDirectory: _syncDirectory(workspaceId).path,
    );
    return SyncStateItem(
      pendingConflicts: value.pendingConflicts,
      restorePending: value.restorePending,
      attachmentConflict: value.attachmentConflict,
    );
  }

  @override
  Future<String?> chooseDiagnosticsExportPath() async {
    final destination = await FilePicker.saveFile(
      dialogTitle: 'Export redacted sync diagnostics',
      fileName: 'authenticator-sync-diagnostics.json',
      type: FileType.custom,
      allowedExtensions: const ['json'],
      bytes: Uint8List(0),
    );
    if (destination == null) return null;
    if (destination.scheme != 'file') {
      throw UnsupportedError('The selected destination is not a local file.');
    }
    return destination.toFilePath();
  }

  @override
  Future<void> exportSyncDiagnostics(String workspaceId, String path) =>
      native.exportSyncDiagnostics(
        stateDirectory: _syncDirectory(workspaceId).path,
        destinationPath: path,
      );

  @override
  Future<void> clearSyncDiagnostics(String workspaceId) => native
      .clearSyncDiagnostics(stateDirectory: _syncDirectory(workspaceId).path);

  @override
  Future<void> setAutoLockSeconds(int seconds) async {
    if (!const [0, 30, 60, 300, 900].contains(seconds)) {
      throw ArgumentError.value(seconds);
    }
    autoLockSeconds = seconds;
    await _writeRegistry(await loadWorkspaces());
  }

  @override
  Future<void> setStalePasswordDays(int days) async {
    if (!const [0, 90, 180, 365].contains(days)) {
      throw ArgumentError.value(days);
    }
    stalePasswordDays = days;
    await _writeRegistry(await loadWorkspaces());
  }

  @override
  Future<void> setThemePreference(AppThemePreference theme) async {
    preferences.value = preferences.value.copyWith(theme: theme);
    await _writeRegistry(await loadWorkspaces());
  }

  @override
  Future<void> setLanguage(AppLanguage language) async {
    preferences.value = preferences.value.copyWith(language: language);
    await _writeRegistry(await loadWorkspaces());
  }

  @override
  Future<String> setPasswordSymbols(String symbols) async {
    final normalized = _normalizePasswordSymbols(symbols);
    if (normalized.isEmpty) throw ArgumentError.value(symbols);
    preferences.value = preferences.value.copyWith(passwordSymbols: normalized);
    await _writeRegistry(await loadWorkspaces());
    return normalized;
  }

  @override
  Future<List<WorkspaceInfo>> saveWorkspaceSync(
    WorkspaceInfo workspace,
    WorkspaceSyncSettings settings, {
    String? password,
  }) async {
    final key = _webDavPasswordKey(workspace.id);
    final shouldStore =
        settings.passwordStored && password != null && password.isNotEmpty;
    if (shouldStore) {
      await _secureStorage.write(key: key, value: password);
    } else if (!settings.passwordStored) {
      await _secureStorage.delete(key: key);
    }
    final persisted = WorkspaceSyncSettings(
      endpoint: settings.endpoint.trim(),
      username: settings.username,
      allowInsecureHttp: settings.allowInsecureHttp,
      autoSync: settings.autoSync,
      nonMeteredOnly: settings.nonMeteredOnly,
      passwordStored: settings.passwordStored,
    );
    final updated = (await loadWorkspaces())
        .map(
          (item) =>
              item.id == workspace.id ? item.copyWith(sync: persisted) : item,
        )
        .toList(growable: false);
    await _writeRegistry(updated);
    return updated;
  }

  @override
  Future<SyncSummary> syncConfiguredWorkspace(
    BigInt handleId,
    WorkspaceInfo workspace, {
    String? passwordOverride,
  }) async {
    final config = workspace.sync;
    if (!config.configured) throw StateError('sync is not configured');
    final password = passwordOverride?.isNotEmpty == true
        ? passwordOverride
        : await _secureStorage.read(key: _webDavPasswordKey(workspace.id));
    if (password == null || password.isEmpty) {
      throw StateError('sync credentials are unavailable');
    }
    return syncWebDav(
      handleId,
      workspace.id,
      WebDavSettings(
        endpoint: config.endpoint,
        username: config.username,
        password: password,
        allowInsecureHttp: config.allowInsecureHttp,
      ),
    );
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
              _vaultFormats[value.handleId] = (
                writable: value.writable,
                format: _formatName(value.format),
              );
              return UnlockedWorkspace(
                workspace: byId[value.workspaceId]!,
                handleId: value.handleId,
                writable: value.writable,
                format: _formatName(value.format),
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

  Directory _syncDirectory(String workspaceId) => Directory(
    '${_vaultDirectory.path}${Platform.pathSeparator}backups'
    '${Platform.pathSeparator}$workspaceId',
  );

  void _rememberHandle(native.VaultHandle handle) {
    _vaultFormats[handle.id] = (
      writable: handle.writable,
      format: _formatName(handle.format),
    );
  }

  Future<void> _writeRegistry(List<WorkspaceInfo> workspaces) async {
    final temporary = File('${_registryFile.path}.tmp');
    await temporary.writeAsString(
      jsonEncode({
        'version': 3,
        'autoLockSeconds': autoLockSeconds,
        'stalePasswordDays': stalePasswordDays,
        'themeMode': _themePreferenceToJson(preferences.value.theme),
        'locale': _languageToJson(preferences.value.language),
        'passwordSymbols': preferences.value.passwordSymbols,
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

String _formatName(native.VaultFormatView value) => switch (value) {
  native.VaultFormatView.kdbx41 => 'KDBX 4.1',
  native.VaultFormatView.kdbx40ReadOnly => 'KDBX 4.0',
  native.VaultFormatView.otherReadOnly => 'KDBX',
};

SyncAction _fromNativeSyncAction(native.SyncActionView value) =>
    switch (value) {
      native.SyncActionView.createdRemote => SyncAction.createdRemote,
      native.SyncActionView.uploaded => SyncAction.uploaded,
      native.SyncActionView.downloaded => SyncAction.downloaded,
      native.SyncActionView.merged => SyncAction.merged,
      native.SyncActionView.unchanged => SyncAction.unchanged,
    };

native.ConflictChoiceView _toNativeConflictChoice(SyncConflictChoice value) =>
    switch (value) {
      SyncConflictChoice.primary => native.ConflictChoiceView.primary,
      SyncConflictChoice.alternate => native.ConflictChoiceView.alternate,
    };

SyncSummary _fromNativeSyncResult(native.SyncResult result) => SyncSummary(
  attempts: result.attempts,
  merged: result.merged,
  action: _fromNativeSyncAction(result.action),
  autoMergedObjects: result.autoMergedObjects,
  createdConflicts: result.createdConflicts,
  pendingConflicts: result.pendingConflicts,
  baselineRebuilt: result.baselineRebuilt,
);

VaultIconItem _fromNativeIcon(native.VaultIconView icon) => VaultIconItem(
  type: switch (icon.kind) {
    native.VaultIconKind.none => VaultIconType.none,
    native.VaultIconKind.builtIn => VaultIconType.builtIn,
    native.VaultIconKind.custom => VaultIconType.custom,
  },
  builtInId: icon.builtInId?.toInt(),
  customId: icon.customId,
);

VaultAttachmentItem _fromNativeAttachment(native.VaultAttachmentView value) =>
    VaultAttachmentItem(
      name: value.name,
      size: value.size.toInt(),
      isProtected: value.isProtected,
    );

PasswordHealthRisk _fromNativeHealthRisk(native.HealthRiskView value) =>
    switch (value) {
      native.HealthRiskView.empty => PasswordHealthRisk.empty,
      native.HealthRiskView.duplicate => PasswordHealthRisk.duplicate,
      native.HealthRiskView.weak => PasswordHealthRisk.weak,
      native.HealthRiskView.stale => PasswordHealthRisk.stale,
      native.HealthRiskView.missingOtp => PasswordHealthRisk.missingOtp,
    };

String _webDavPasswordKey(String workspaceId) =>
    'authenticator_vault.webdav.$workspaceId.password';

String _themePreferenceToJson(AppThemePreference value) => value.name;

AppThemePreference _themePreferenceFromJson(String value) => switch (value) {
  'system' => AppThemePreference.system,
  'light' => AppThemePreference.light,
  'dark' => AppThemePreference.dark,
  _ => throw const FormatException(),
};

String _languageToJson(AppLanguage value) => switch (value) {
  AppLanguage.zhHans => 'zh_CN',
  AppLanguage.english => 'en',
};

AppLanguage _languageFromJson(String value) => switch (value) {
  'zh_CN' => AppLanguage.zhHans,
  'en' => AppLanguage.english,
  _ => throw const FormatException(),
};
