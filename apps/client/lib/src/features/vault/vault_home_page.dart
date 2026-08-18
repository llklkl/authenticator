import 'dart:async';

import 'package:authenticator_vault/src/features/settings/settings_page.dart';
import 'package:authenticator_vault/src/features/security/platform_security_service.dart';
import 'package:authenticator_vault/src/features/vault/desktop_title_bar.dart';
import 'package:authenticator_vault/src/features/vault/vault_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:connectivity_plus/connectivity_plus.dart';

enum _VaultSection { passwords, otp, other }

enum _SmartFilter { none, favorites, recent }

enum _WorkspaceSyncState {
  unconfigured,
  credentialsNeeded,
  waitingNetwork,
  pending,
  syncing,
  synced,
  failed,
}

class VaultHomePage extends StatefulWidget {
  const VaultHomePage({required this.vaultService, super.key});

  final VaultService vaultService;

  @override
  State<VaultHomePage> createState() => _VaultHomePageState();
}

class _VaultHomePageState extends State<VaultHomePage>
    with WidgetsBindingObserver {
  final _handles = <String, BigInt>{};
  final _entries = <String, List<VaultEntryItem>>{};
  final _contents = <String, VaultContent>{};
  final _selectedGroups = <String, String>{};
  final _codes = <String, OtpValue>{};
  final _searchController = TextEditingController();
  List<WorkspaceInfo> _workspaces = [];
  String? _selectedId;
  String _query = '';
  String? _selectedEntryId;
  String? _revealedPassword;
  _VaultSection _section = _VaultSection.passwords;
  _SmartFilter _smartFilter = _SmartFilter.none;
  String? _selectedTag;
  double _treeWidth = 260;
  double _listFraction = 0.58;
  bool _loading = true;
  bool _privacyOverlay = false;
  Object? _loadError;
  Timer? _ticker;
  Timer? _passwordHideTimer;
  Stopwatch? _backgroundElapsed;
  StreamSubscription<void>? _screenOffSubscription;
  StreamSubscription<List<ConnectivityResult>>? _connectivitySubscription;
  Timer? _periodicSyncTimer;
  final _syncTimers = <String, Timer>{};
  final _syncStates = <String, _WorkspaceSyncState>{};
  final _syncAttempts = <String, int>{};
  final _syncing = <String>{};
  final _customIconLoads = <String, Future<Uint8List>>{};
  bool _foreground = true;
  late final SecurityCoordinator _securityCoordinator;

  SecurityVaultService? get _securityService =>
      widget.vaultService is SecurityVaultService
      ? widget.vaultService as SecurityVaultService
      : null;

  WorkspaceInfo? get _selected =>
      _workspaces.where((workspace) => workspace.id == _selectedId).firstOrNull;

  BigInt? get _selectedHandle => _handles[_selectedId];
  List<VaultEntryItem> get _selectedEntries =>
      _entries[_selectedId] ?? const [];
  VaultContent? get _selectedContent => _contents[_selectedId];
  String? get _selectedGroupId => _selectedId == null
      ? null
      : _selectedGroups[_selectedId!] ?? _selectedContent?.rootGroupId;
  VaultEntryItem? get _selectedEntry => _selectedEntries
      .where((entry) => entry.id == _selectedEntryId)
      .firstOrNull;
  StructuredVaultService? get _structuredService =>
      widget.vaultService is StructuredVaultService
      ? widget.vaultService as StructuredVaultService
      : null;
  ProductivityVaultService? get _productivityService =>
      widget.vaultService is ProductivityVaultService
      ? widget.vaultService as ProductivityVaultService
      : null;

  @override
  void initState() {
    super.initState();
    _securityCoordinator = SecurityCoordinator(
      _securityService?.platformSecurity ?? const NoopPlatformSecurityService(),
    );
    WidgetsBinding.instance.addObserver(this);
    _screenOffSubscription = _securityService?.platformSecurity.screenOffEvents
        .listen((_) => unawaited(_lockAll()));
    unawaited(_loadWorkspaces());
    _ticker = Timer.periodic(const Duration(seconds: 1), (_) => _refreshOtp());
    _connectivitySubscription = Connectivity().onConnectivityChanged.listen(
      (_) => _scheduleAllAutoSync(const Duration(seconds: 2)),
    );
    _periodicSyncTimer = Timer.periodic(
      const Duration(minutes: 5),
      (_) => _scheduleAllAutoSync(Duration.zero),
    );
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden ||
        state == AppLifecycleState.detached) {
      _hidePassword();
      _foreground = false;
      _backgroundElapsed ??= Stopwatch()..start();
      if (mounted) setState(() => _privacyOverlay = true);
      unawaited(_securityCoordinator.setBackgrounded(true));
    } else if (state == AppLifecycleState.resumed) {
      _foreground = true;
      unawaited(_resumeFromBackground());
    }
  }

  Future<void> _resumeFromBackground() async {
    final elapsed = _backgroundElapsed?.elapsed ?? Duration.zero;
    _backgroundElapsed?.stop();
    _backgroundElapsed = null;
    final timeout = _securityService?.autoLockSeconds ?? 300;
    if (shouldAutoLock(
      hasUnlockedWorkspaces: _handles.isNotEmpty,
      backgroundElapsed: elapsed,
      timeoutSeconds: timeout,
    )) {
      await _lockAll();
    }
    await _securityCoordinator.setBackgrounded(false);
    _scheduleAllAutoSync(const Duration(seconds: 2));
    if (mounted) setState(() => _privacyOverlay = false);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _ticker?.cancel();
    _passwordHideTimer?.cancel();
    unawaited(_screenOffSubscription?.cancel());
    unawaited(_connectivitySubscription?.cancel());
    _periodicSyncTimer?.cancel();
    for (final timer in _syncTimers.values) {
      timer.cancel();
    }
    _searchController.dispose();
    unawaited(widget.vaultService.lockAll());
    super.dispose();
  }

  Future<void> _loadWorkspaces() async {
    try {
      final workspaces = await widget.vaultService.loadWorkspaces();
      if (!mounted) return;
      setState(() {
        _workspaces = workspaces;
        _selectedId = workspaces.firstOrNull?.id;
        _loading = false;
      });
    } on Object catch (error) {
      if (!mounted) return;
      setState(() {
        _loadError = error;
        _loading = false;
      });
    }
  }

  Future<T?> _sensitiveDialog<T>({required WidgetBuilder builder}) =>
      _securityCoordinator.sensitive(
        () => showDialog<T>(context: context, builder: builder),
      );

  Future<void> _createWorkspace() async {
    final request = await _sensitiveDialog<_CreateWorkspaceRequest>(
      builder: (_) => const _CreateWorkspaceDialog(),
    );
    if (request == null || !mounted) return;
    await _guarded(() async {
      final unlocked = await widget.vaultService.createWorkspace(
        request.name,
        request.password,
      );
      setState(() {
        _workspaces = [..._workspaces, unlocked.workspace];
        _selectedId = unlocked.workspace.id;
        _handles[unlocked.workspace.id] = unlocked.handleId;
        _entries[unlocked.workspace.id] = [];
      });
      await _securityCoordinator.setUnlockedCount(_handles.length);
      await _refreshEntries();
    }, success: 'Workspace 已创建，本地文件使用 KDBX 4.1 加密。');
  }

  Future<void> _importWorkspace() async {
    final selectedPath = await widget.vaultService.chooseKdbxFile();
    if (selectedPath == null || !mounted) return;
    final request = await _sensitiveDialog<_ImportWorkspaceRequest>(
      builder: (_) => _ImportWorkspaceDialog(initialPath: selectedPath),
    );
    if (request == null || !mounted) return;
    await _guarded(() async {
      final unlocked = await widget.vaultService.importWorkspace(
        request.name,
        request.path,
        request.password,
      );
      setState(() {
        _workspaces = [..._workspaces, unlocked.workspace];
        _selectedId = unlocked.workspace.id;
        _handles[unlocked.workspace.id] = unlocked.handleId;
        _entries[unlocked.workspace.id] = [];
      });
      await _securityCoordinator.setUnlockedCount(_handles.length);
      await _refreshEntries();
      await _refreshOtp();
    }, success: 'KDBX Workspace 已导入。');
  }

  Future<void> _unlock() async {
    final workspace = _selected;
    if (workspace == null) return;
    final password = await _sensitiveDialog<String>(
      builder: (_) => _PasswordDialog(workspaceName: workspace.name),
    );
    if (password == null || !mounted) return;
    await _guarded(() async {
      final handle = await widget.vaultService.unlock(workspace, password);
      setState(() {
        _handles[workspace.id] = handle;
      });
      await _securityCoordinator.setUnlockedCount(_handles.length);
      await _refreshEntries();
      await _refreshOtp();
    });
  }

  Future<void> _lockAll() async {
    await widget.vaultService.lockAll();
    if (!mounted) return;
    setState(() {
      _handles.clear();
      _entries.clear();
      _contents.clear();
      _codes.clear();
      _passwordHideTimer?.cancel();
      _passwordHideTimer = null;
      _revealedPassword = null;
      _syncing.clear();
      _customIconLoads.clear();
    });
    for (final timer in _syncTimers.values) {
      timer.cancel();
    }
    _syncTimers.clear();
    PaintingBinding.instance.imageCache
      ..clear()
      ..clearLiveImages();
    await _securityCoordinator.setUnlockedCount(0);
  }

  Future<void> _refreshEntries({bool scheduleSync = true}) async {
    final handle = _selectedHandle;
    final workspace = _selected;
    if (handle == null || workspace == null) return;
    final structured = _structuredService;
    final content = structured == null
        ? null
        : await structured.content(handle);
    final entries =
        content?.entries ?? await widget.vaultService.listEntries(handle);
    if (!mounted || handle != _handles[workspace.id]) return;
    setState(() {
      _entries[workspace.id] = entries;
      if (content != null) {
        _contents[workspace.id] = content;
        _selectedGroups.putIfAbsent(workspace.id, () => content.rootGroupId);
      }
      if (_selectedEntryId != null &&
          !entries.any((entry) => entry.id == _selectedEntryId)) {
        _selectedEntryId = null;
        _passwordHideTimer?.cancel();
        _passwordHideTimer = null;
        _revealedPassword = null;
      }
    });
    await _refreshOtp();
    if (scheduleSync) {
      _scheduleAutoSync(workspace.id, const Duration(seconds: 2));
    }
  }

  Future<void> _refreshOtp() async {
    final handle = _selectedHandle;
    if (handle == null) return;
    final otpEntries = _selectedEntries.where((entry) => entry.hasOtp).toList();
    if (otpEntries.isEmpty) return;
    final now = DateTime.now();
    final values = await Future.wait(
      otpEntries.map((entry) async {
        try {
          return MapEntry(
            entry.id,
            await widget.vaultService.currentOtp(handle, entry.id, now),
          );
        } on Object {
          return null;
        }
      }),
    );
    if (!mounted || handle != _selectedHandle) return;
    setState(() {
      for (final value in values.nonNulls) {
        _codes[value.key] = value.value;
      }
    });
  }

  Future<void> _addEntry([EntryType initialType = EntryType.login]) async {
    final handle = _selectedHandle;
    if (handle == null) return;
    final draft = await _sensitiveDialog<VaultEntryDraft>(
      builder: (_) => _EntryEditorDialog(initialType: initialType),
    );
    if (draft == null || !mounted) return;
    await _guarded(() async {
      final groupId = _selectedGroupId;
      final structured = _structuredService;
      if (structured != null && groupId != null) {
        await structured.createEntryInGroup(handle, groupId, draft);
      } else {
        await widget.vaultService.createEntry(handle, draft);
      }
      await _refreshEntries();
    }, success: '条目已保存。');
  }

  Future<void> _importOtp() async {
    final handle = _selectedHandle;
    if (handle == null) return;
    final uri = await _sensitiveDialog<String>(
      builder: (_) => const _OtpImportDialog(),
    );
    if (uri == null || !mounted) return;
    await _guarded(() async {
      await widget.vaultService.importOtp(handle, uri);
      await _refreshEntries();
    }, success: 'OTP 已写入加密 Vault。');
  }

  Future<void> _openSettings() async {
    final service = _productivityService;
    if (service == null) return;
    await Navigator.of(context).push<void>(
      MaterialPageRoute(
        builder: (_) => SettingsPage(
          service: service,
          workspaces: _workspaces,
          selectedWorkspaceId: _selectedId,
          handles: Map.of(_handles),
          onWorkspacesChanged: (value) {
            if (mounted) setState(() => _workspaces = value);
          },
          onVaultChanged: () => unawaited(_refreshEntries(scheduleSync: false)),
        ),
      ),
    );
    if (mounted) {
      setState(() {});
      _scheduleAllAutoSync(const Duration(seconds: 2));
    }
  }

  void _scheduleAllAutoSync(Duration delay) {
    for (final workspace in _workspaces) {
      if (_handles.containsKey(workspace.id)) {
        _scheduleAutoSync(workspace.id, delay);
      }
    }
  }

  void _scheduleAutoSync(String workspaceId, Duration delay) {
    final workspace = _workspaces
        .where((item) => item.id == workspaceId)
        .firstOrNull;
    if (!_foreground ||
        workspace == null ||
        !workspace.sync.configured ||
        !workspace.sync.autoSync ||
        !_handles.containsKey(workspaceId) ||
        _productivityService == null) {
      if (workspace != null && !workspace.sync.configured) {
        _setSyncState(workspaceId, _WorkspaceSyncState.unconfigured);
      }
      return;
    }
    if (!workspace.sync.passwordStored) {
      _setSyncState(workspaceId, _WorkspaceSyncState.credentialsNeeded);
      return;
    }
    _syncTimers[workspaceId]?.cancel();
    _setSyncState(workspaceId, _WorkspaceSyncState.pending);
    _syncTimers[workspaceId] = Timer(
      delay,
      () => unawaited(_runAutoSync(workspaceId)),
    );
  }

  Future<void> _runAutoSync(String workspaceId) async {
    if (!_foreground || _syncing.contains(workspaceId)) return;
    final service = _productivityService;
    final workspace = _workspaces
        .where((item) => item.id == workspaceId)
        .firstOrNull;
    final handle = _handles[workspaceId];
    if (service == null || workspace == null || handle == null) return;
    final connections = await Connectivity().checkConnectivity();
    final offline =
        connections.isEmpty || connections.contains(ConnectivityResult.none);
    final metered = connections.contains(ConnectivityResult.mobile);
    if (offline || (workspace.sync.nonMeteredOnly && metered)) {
      _setSyncState(workspaceId, _WorkspaceSyncState.waitingNetwork);
      return;
    }
    _syncing.add(workspaceId);
    _setSyncState(workspaceId, _WorkspaceSyncState.syncing);
    try {
      await service.syncConfiguredWorkspace(handle, workspace);
      _syncAttempts[workspaceId] = 0;
      _setSyncState(workspaceId, _WorkspaceSyncState.synced);
      if (workspaceId == _selectedId) {
        await _refreshEntries(scheduleSync: false);
      }
    } on StateError {
      _syncAttempts[workspaceId] = 0;
      _setSyncState(workspaceId, _WorkspaceSyncState.credentialsNeeded);
    } on Object {
      final attempt = (_syncAttempts[workspaceId] ?? 0) + 1;
      _syncAttempts[workspaceId] = attempt;
      _setSyncState(workspaceId, _WorkspaceSyncState.failed);
      const retries = [5, 30, 120, 600, 900];
      final seconds = retries[(attempt - 1).clamp(0, retries.length - 1)];
      if (_foreground) {
        _syncTimers[workspaceId]?.cancel();
        _syncTimers[workspaceId] = Timer(
          Duration(seconds: seconds),
          () => unawaited(_runAutoSync(workspaceId)),
        );
      }
    } finally {
      _syncing.remove(workspaceId);
    }
  }

  void _setSyncState(String workspaceId, _WorkspaceSyncState state) {
    if (!mounted || _syncStates[workspaceId] == state) return;
    setState(() => _syncStates[workspaceId] = state);
  }

  Future<void> _editEntry(VaultEntryItem item) async {
    final handle = _selectedHandle;
    if (handle == null) return;
    var password = '';
    var notes = '';
    try {
      if (item.hasPassword) {
        password = await widget.vaultService.revealPassword(handle, item.id);
      }
      notes = await widget.vaultService.revealNotes(handle, item.id);
    } on Object {
      // Imported databases may omit one of the standard protected fields.
    }
    if (!mounted) return;
    final draft = await _sensitiveDialog<VaultEntryDraft>(
      builder: (_) => _EntryEditorDialog(
        initialType: item.type,
        initial: VaultEntryDraft(
          type: item.type,
          title: item.title,
          username: item.username,
          password: password,
          url: item.url,
          notes: notes,
          tags: item.tags,
          preserveExistingOtp: item.hasOtp,
        ),
      ),
    );
    if (draft == null || !mounted) return;
    await _guarded(() async {
      await widget.vaultService.updateEntry(handle, item.id, draft);
      await _refreshEntries();
    }, success: '条目已更新。');
  }

  Future<void> _deleteEntry(VaultEntryItem item) async {
    final handle = _selectedHandle;
    if (handle == null) return;
    final content = _selectedContent;
    final structured = _structuredService;
    if (structured != null && !item.isInRecycleBin) {
      if (content?.recycleBinEnabled == true) {
        await _guarded(() async {
          await structured.trashEntry(handle, item.id);
          await _refreshEntries();
        }, success: '条目已移至回收站。');
        return;
      }
      final action = await _sensitiveDialog<String>(
        builder: (context) => AlertDialog(
          title: const Text('此 Workspace 未启用回收站'),
          content: const Text('可以先启用回收站并安全删除，或永久删除此条目。'),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('取消'),
            ),
            TextButton(
              onPressed: () => Navigator.pop(context, 'permanent'),
              child: const Text('永久删除'),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(context, 'enable'),
              child: const Text('启用并移入回收站'),
            ),
          ],
        ),
      );
      if (action == null || !mounted) return;
      await _guarded(() async {
        if (action == 'enable') {
          await structured.enableRecycleBin(handle);
          await structured.trashEntry(handle, item.id);
        } else {
          await widget.vaultService.deleteEntry(handle, item.id);
        }
        await _refreshEntries();
      });
      return;
    }
    final confirmed = await _sensitiveDialog<bool>(
      builder: (context) => AlertDialog(
        title: const Text('永久删除条目？'),
        content: Text('“${item.title}”将无法从回收站恢复。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('永久删除'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await _guarded(() async {
      await widget.vaultService.deleteEntry(handle, item.id);
      _codes.remove(item.id);
      await _refreshEntries();
    });
  }

  Future<void> _reveal(VaultEntryItem item, bool notes) async {
    final handle = _selectedHandle;
    if (handle == null) return;
    await _guarded(() async {
      final value = notes
          ? await widget.vaultService.revealNotes(handle, item.id)
          : await widget.vaultService.revealPassword(handle, item.id);
      if (!mounted) return;
      await _sensitiveDialog<void>(
        builder: (context) => AlertDialog(
          title: Text(notes ? '受保护内容' : '密码'),
          content: SelectableText(value.isEmpty ? '（空）' : value),
          actions: [
            TextButton(onPressed: () => _copy(value), child: const Text('复制')),
            FilledButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('关闭'),
            ),
          ],
        ),
      );
    });
  }

  Future<void> _togglePassword(VaultEntryItem item) async {
    if (_revealedPassword != null) {
      _hidePassword();
      return;
    }
    final handle = _selectedHandle;
    if (handle == null) return;
    await _guarded(() async {
      final password = await widget.vaultService.revealPassword(
        handle,
        item.id,
      );
      if (!mounted || _selectedEntryId != item.id) return;
      _passwordHideTimer?.cancel();
      setState(() => _revealedPassword = password);
      _passwordHideTimer = Timer(const Duration(seconds: 30), _hidePassword);
    });
  }

  void _hidePassword() {
    _passwordHideTimer?.cancel();
    _passwordHideTimer = null;
    if (_revealedPassword == null) return;
    if (mounted) {
      setState(() => _revealedPassword = null);
    } else {
      _revealedPassword = null;
    }
  }

  Future<void> _selectWorkspace(String id) async {
    if (_selectedId == id) return;
    _hidePassword();
    setState(() {
      _selectedId = id;
      _selectedEntryId = null;
      _smartFilter = _SmartFilter.none;
      _selectedTag = null;
    });
    if (_handles.containsKey(id) &&
        (!_entries.containsKey(id) ||
            (_structuredService != null && !_contents.containsKey(id)))) {
      await _refreshEntries();
    } else {
      await _refreshOtp();
    }
  }

  void _selectGroup(String groupId) {
    final workspaceId = _selectedId;
    if (workspaceId == null) return;
    _hidePassword();
    setState(() {
      _selectedGroups[workspaceId] = groupId;
      _selectedEntryId = null;
      _smartFilter = _SmartFilter.none;
      _selectedTag = null;
    });
  }

  void _selectEntry(VaultEntryItem item) {
    _hidePassword();
    setState(() => _selectedEntryId = item.id);
  }

  Future<String?> _askName(String title, {String initial = ''}) async {
    final controller = TextEditingController(text: initial);
    final value = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(title),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(labelText: '名称'),
          onSubmitted: (value) => Navigator.pop(context, value),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, controller.text),
            child: const Text('确定'),
          ),
        ],
      ),
    );
    controller.dispose();
    return value?.trim();
  }

  Future<void> _chooseFolderIcon(VaultGroupItem group) async {
    final service = _productivityService;
    final handle = _selectedHandle;
    if (service == null || handle == null) return;
    final selected = await showDialog<int>(
      context: context,
      builder: (context) => _FolderIconDialog(current: group.icon.builtInId),
    );
    if (!mounted || selected == null || selected == -2) return;
    await _guarded(() async {
      await service.setGroupIcon(
        handle,
        group.id,
        selected == -1 ? null : selected,
      );
      await _refreshEntries();
    }, success: '文件夹图标已更新。');
  }

  Future<void> _toggleFavorite(VaultEntryItem item) async {
    final service = _productivityService;
    final handle = _selectedHandle;
    if (service == null || handle == null) return;
    await _guarded(() async {
      await service.setFavorite(handle, item.id, !item.isFavorite);
      await _refreshEntries();
    });
  }

  Future<void> _addAttachment(VaultEntryItem item) async {
    final service = _productivityService;
    final handle = _selectedHandle;
    if (service == null || handle == null) return;
    final path = await service.chooseAttachmentFile();
    if (path == null || !mounted) return;
    final name = path.replaceAll('\\', '/').split('/').last;
    await _guarded(() async {
      await service.addAttachment(handle, item.id, name, path);
      await _refreshEntries();
    }, success: '附件已加密保存到 KDBX。');
  }

  Future<void> _exportAttachment(
    VaultEntryItem item,
    VaultAttachmentItem attachment,
  ) async {
    final service = _productivityService;
    final handle = _selectedHandle;
    if (service == null || handle == null) return;
    final destination = await service.chooseAttachmentExportPath(
      attachment.name,
    );
    if (destination == null || !mounted) return;
    await _guarded(() async {
      await service.exportAttachment(
        handle,
        item.id,
        attachment.name,
        destination,
      );
    }, success: '附件已导出。');
  }

  Future<void> _renameAttachment(
    VaultEntryItem item,
    VaultAttachmentItem attachment,
  ) async {
    final service = _productivityService;
    final handle = _selectedHandle;
    if (service == null || handle == null) return;
    final name = await _askName('重命名附件', initial: attachment.name);
    if (name == null || !mounted) return;
    await _guarded(() async {
      await service.renameAttachment(handle, item.id, attachment.name, name);
      await _refreshEntries();
    });
  }

  Future<void> _removeAttachment(
    VaultEntryItem item,
    VaultAttachmentItem attachment,
  ) async {
    final service = _productivityService;
    final handle = _selectedHandle;
    if (service == null || handle == null) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('删除附件？'),
        content: Text('“${attachment.name}”将从当前条目移除。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('删除'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await _guarded(() async {
      await service.removeAttachment(handle, item.id, attachment.name);
      await _refreshEntries();
    });
  }

  Future<void> _showPasswordGenerator() async {
    final service = _productivityService;
    if (service == null) return;
    final value = await showDialog<String>(
      context: context,
      builder: (_) => _PasswordGeneratorDialog(service: service),
    );
    if (value != null && mounted) await _copy(value);
  }

  Future<void> _createFolder([String? parentId]) async {
    final handle = _selectedHandle;
    final structured = _structuredService;
    final parent = parentId ?? _selectedGroupId;
    if (handle == null || structured == null || parent == null) return;
    final request = await showDialog<_CreateFolderRequest>(
      context: context,
      builder: (_) => const _CreateFolderDialog(),
    );
    if (request == null || !mounted) return;
    await _guarded(() async {
      final id = await structured.createGroup(
        handle,
        parent,
        request.name,
        iconId: request.iconId,
      );
      await _refreshEntries();
      _selectGroup(id);
    });
  }

  Future<void> _renameFolder(VaultGroupItem group) async {
    final handle = _selectedHandle;
    final structured = _structuredService;
    if (handle == null || structured == null) return;
    final name = await _askName('重命名文件夹', initial: group.name);
    if (name == null || name.isEmpty || !mounted) return;
    await _guarded(() async {
      await structured.renameGroup(handle, group.id, name);
      await _refreshEntries();
    });
  }

  Future<void> _trashFolder(VaultGroupItem group) async {
    final handle = _selectedHandle;
    final structured = _structuredService;
    if (handle == null || structured == null) return;
    await _guarded(() async {
      await structured.trashGroup(handle, group.id);
      _selectedGroups[_selectedId!] = _selectedContent!.rootGroupId;
      await _refreshEntries();
    }, success: '文件夹已移至回收站。');
  }

  Future<void> _moveFolderTo(VaultGroupItem group) async {
    final handle = _selectedHandle;
    final structured = _structuredService;
    final content = _selectedContent;
    if (handle == null || structured == null || content == null) return;
    final descendants = _descendantGroupIds(group.id);
    final candidates = content.groups
        .where(
          (candidate) =>
              !candidate.isRecycleBin &&
              !descendants.contains(candidate.id) &&
              !_isInsideRecycle(candidate.id),
        )
        .toList(growable: false);
    final destination = await showDialog<String>(
      context: context,
      builder: (context) => SimpleDialog(
        title: const Text('移动文件夹到…'),
        children: [
          for (final candidate in candidates)
            SimpleDialogOption(
              onPressed: () => Navigator.pop(context, candidate.id),
              child: Text(_groupPath(candidate.id)),
            ),
        ],
      ),
    );
    if (destination == null || !mounted) return;
    await _guarded(() async {
      await structured.moveGroup(handle, group.id, destination);
      await _refreshEntries();
    });
  }

  Future<void> _restoreEntry(VaultEntryItem entry) async {
    final handle = _selectedHandle;
    final structured = _structuredService;
    if (handle == null || structured == null) return;
    await _guarded(() async {
      await structured.restoreEntry(handle, entry.id);
      await _refreshEntries();
    }, success: '条目已恢复。');
  }

  Future<void> _restoreFolder(VaultGroupItem group) async {
    final handle = _selectedHandle;
    final structured = _structuredService;
    if (handle == null || structured == null) return;
    await _guarded(() async {
      await structured.restoreGroup(handle, group.id);
      await _refreshEntries();
    }, success: '文件夹已恢复。');
  }

  Future<void> _deleteFolderPermanently(VaultGroupItem group) async {
    final handle = _selectedHandle;
    final structured = _structuredService;
    if (handle == null || structured == null) return;
    await _guarded(() async {
      await structured.permanentlyDeleteGroup(handle, group.id);
      _selectedGroups[_selectedId!] = _selectedContent!.rootGroupId;
      await _refreshEntries();
    });
  }

  Future<void> _moveEntryTo(VaultEntryItem entry) async {
    final handle = _selectedHandle;
    final structured = _structuredService;
    final content = _selectedContent;
    if (handle == null || structured == null || content == null) return;
    final candidates = content.groups
        .where((group) => !group.isRecycleBin && !_isInsideRecycle(group.id))
        .toList(growable: false);
    final destination = await showDialog<String>(
      context: context,
      builder: (context) => SimpleDialog(
        title: const Text('移动到…'),
        children: [
          for (final group in candidates)
            SimpleDialogOption(
              onPressed: () => Navigator.pop(context, group.id),
              child: Text(_groupPath(group.id)),
            ),
        ],
      ),
    );
    if (destination == null || !mounted) return;
    await _guarded(() async {
      await structured.moveEntry(handle, entry.id, destination);
      await _refreshEntries();
    });
  }

  bool _isInsideRecycle(String groupId) {
    final content = _selectedContent;
    final recycleId = content?.recycleBinId;
    if (content == null || recycleId == null) return false;
    var current = content.groups
        .where((group) => group.id == groupId)
        .firstOrNull;
    while (current != null) {
      if (current.id == recycleId) return true;
      final parentId = current.parentId;
      current = parentId == null
          ? null
          : content.groups.where((group) => group.id == parentId).firstOrNull;
    }
    return false;
  }

  String _groupPath(String groupId) {
    final content = _selectedContent;
    if (content == null) return '';
    final names = <String>[];
    var current = content.groups
        .where((group) => group.id == groupId)
        .firstOrNull;
    while (current != null) {
      names.add(current.name);
      final parentId = current.parentId;
      current = parentId == null
          ? null
          : content.groups.where((group) => group.id == parentId).firstOrNull;
    }
    return names.reversed.join(' / ');
  }

  Future<void> _emptyRecycleBin() async {
    final handle = _selectedHandle;
    final structured = _structuredService;
    if (handle == null || structured == null) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('清空回收站？'),
        content: const Text('其中的文件夹和条目都将永久删除。'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('清空'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await _guarded(() async {
      await structured.emptyRecycleBin(handle);
      await _refreshEntries();
    });
  }

  Future<void> _copy(String value) async {
    await Clipboard.setData(ClipboardData(text: value));
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(const SnackBar(content: Text('已复制，30 秒后尝试清除剪贴板。')));
    unawaited(
      Future<void>.delayed(const Duration(seconds: 30), () async {
        final current = await Clipboard.getData(Clipboard.kTextPlain);
        if (current?.text == value) {
          await Clipboard.setData(const ClipboardData(text: ''));
        }
      }),
    );
  }

  Future<void> _quickUnlock() async {
    final service = _securityService;
    final current = _selected;
    if (service == null || current == null) return;
    final available = _workspaces
        .where((item) {
          return item.quickUnlockEnabled && !_handles.containsKey(item.id);
        })
        .toList(growable: false);
    if (available.isEmpty) return;
    final selected = await _sensitiveDialog<List<WorkspaceInfo>>(
      builder: (_) => _QuickUnlockSelectionDialog(
        workspaces: available,
        initiallySelectedId: current.id,
      ),
    );
    if (selected == null || selected.isEmpty || !mounted) return;
    await _guarded(() async {
      final outcome = await service.quickUnlock(selected);
      final entryLists = await Future.wait(
        outcome.opened.map((item) async {
          return MapEntry(
            item.workspace.id,
            await widget.vaultService.listEntries(item.handleId),
          );
        }),
      );
      if (!mounted) return;
      setState(() {
        for (final unlocked in outcome.opened) {
          _handles[unlocked.workspace.id] = unlocked.handleId;
        }
        for (final entries in entryLists) {
          _entries[entries.key] = entries.value;
        }
      });
      await _securityCoordinator.setUnlockedCount(_handles.length);
      await _refreshEntries();
      await _refreshOtp();
      if (outcome.failedIds.isNotEmpty && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('${outcome.failedIds.length} 个 Workspace 解锁失败。'),
          ),
        );
      }
    });
  }

  Future<void> _showSecuritySettings() async {
    final service = _securityService;
    final workspace = _selected;
    if (service == null || workspace == null) return;
    final result = await _sensitiveDialog<_SecuritySettingsResult>(
      builder: (_) => _SecuritySettingsDialog(
        workspace: workspace,
        unlocked: _selectedHandle != null,
        initialAutoLockSeconds: service.autoLockSeconds,
      ),
    );
    if (result == null || !mounted) return;
    await _guarded(() async {
      await service.setAutoLockSeconds(result.autoLockSeconds);
      var updated = _workspaces;
      if (result.quickUnlockEnabled != workspace.quickUnlockEnabled) {
        if (result.quickUnlockEnabled) {
          if (!await service.canQuickUnlock()) {
            throw const PlatformSecurityFailure('notAvailable');
          }
          final handle = _selectedHandle;
          if (handle == null) throw StateError('workspace locked');
          updated = await service.enableQuickUnlock(
            UnlockedWorkspace(workspace: workspace, handleId: handle),
          );
        } else {
          updated = await service.disableQuickUnlock(workspace);
        }
      }
      if (mounted) setState(() => _workspaces = updated);
    }, success: '安全设置已更新。');
  }

  Future<void> _guarded(
    Future<void> Function() operation, {
    String? success,
  }) async {
    try {
      await operation();
      if (success != null && mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text(success)));
      }
    } on Object {
      if (!mounted) return;
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('操作失败。请检查主密码、文件路径或输入格式。')));
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (_loadError != null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Authenticator Vault')),
        body: const Center(
          child: Padding(
            padding: EdgeInsets.all(32),
            child: Text('Workspace 注册表损坏或版本不受支持。原文件未被覆盖，请从备份恢复。'),
          ),
        ),
      );
    }
    return Scaffold(
      body: Stack(
        children: [
          Column(
            children: [
              DesktopTitleBar(
                leading: _buildWorkspaceSwitcher(),
                search: _workspaces.isEmpty || _selectedHandle == null
                    ? const SizedBox()
                    : _buildSearchField(),
                actions: [
                  _buildSyncStatus(),
                  IconButton(
                    onPressed: _productivityService != null
                        ? _openSettings
                        : (_securityService == null || _selected == null
                              ? null
                              : _showSecuritySettings),
                    tooltip: '设置',
                    icon: const Icon(Icons.settings_outlined, size: 20),
                  ),
                  IconButton(
                    onPressed: _handles.isEmpty ? null : _lockAll,
                    tooltip: '锁定全部 Workspace',
                    icon: const Icon(Icons.lock_outline, size: 20),
                  ),
                ],
              ),
              Expanded(
                child: LayoutBuilder(
                  builder: (context, constraints) {
                    if (_workspaces.isEmpty) return _buildWelcome();
                    if (constraints.maxWidth >= 900) {
                      return _buildDesktopWorkspace(constraints);
                    }
                    return _buildMobileWorkspace();
                  },
                ),
              ),
            ],
          ),
          if (_privacyOverlay)
            const Positioned.fill(
              child: ColoredBox(
                color: Color(0xfff7f8fa),
                child: Center(child: Icon(Icons.shield, size: 72)),
              ),
            ),
        ],
      ),
    );
  }

  Widget _buildWelcome() => Center(
    child: ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 520),
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.shield_outlined, size: 72),
            const SizedBox(height: 20),
            Text(
              '创建你的第一个 Workspace',
              style: Theme.of(context).textTheme.headlineSmall,
            ),
            const SizedBox(height: 8),
            const Text('每个 Workspace 是独立的 KDBX 4.1 文件，可使用不同主密码。'),
            const SizedBox(height: 24),
            Wrap(
              spacing: 12,
              runSpacing: 12,
              alignment: WrapAlignment.center,
              children: [
                FilledButton.icon(
                  onPressed: _createWorkspace,
                  icon: const Icon(Icons.add),
                  label: const Text('新建 Workspace'),
                ),
                OutlinedButton.icon(
                  onPressed: _importWorkspace,
                  icon: const Icon(Icons.file_open_outlined),
                  label: const Text('导入现有 KDBX'),
                ),
              ],
            ),
          ],
        ),
      ),
    ),
  );

  Widget _buildWorkspaceSwitcher() => PopupMenuButton<String>(
    tooltip: '切换 Workspace',
    onSelected: (value) {
      if (value == '__create') {
        _createWorkspace();
      } else if (value == '__import') {
        _importWorkspace();
      } else {
        _selectWorkspace(value);
      }
    },
    itemBuilder: (_) => [
      for (final workspace in _workspaces)
        PopupMenuItem(
          value: workspace.id,
          child: Row(
            children: [
              Icon(
                _handles.containsKey(workspace.id)
                    ? Icons.lock_open_outlined
                    : Icons.lock_outline,
                size: 18,
              ),
              const SizedBox(width: 10),
              Flexible(child: Text(workspace.name)),
              if (workspace.id == _selectedId) ...[
                const Spacer(),
                const Icon(Icons.check, size: 18),
              ],
            ],
          ),
        ),
      const PopupMenuDivider(),
      const PopupMenuItem(value: '__create', child: Text('＋ 新建 Workspace')),
      const PopupMenuItem(value: '__import', child: Text('导入 KDBX…')),
    ],
    child: ConstrainedBox(
      constraints: const BoxConstraints(maxWidth: 230),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.shield_outlined, size: 21),
            const SizedBox(width: 9),
            Flexible(
              child: Text(
                _selected?.name ?? 'Authenticator Vault',
                overflow: TextOverflow.ellipsis,
                style: const TextStyle(fontWeight: FontWeight.w600),
              ),
            ),
            const Icon(Icons.expand_more, size: 18),
          ],
        ),
      ),
    ),
  );

  Widget _buildDesktopWorkspace(BoxConstraints constraints) {
    final workspace = _selected;
    if (workspace == null) return const SizedBox();
    if (_selectedHandle == null) {
      return _LockedWorkspace(
        workspace: workspace,
        onUnlock: _unlock,
        onQuickUnlock: workspace.quickUnlockEnabled ? _quickUnlock : null,
      );
    }
    final safeTreeWidth = _treeWidth.clamp(220.0, 360.0);
    return Row(
      children: [
        SizedBox(width: safeTreeWidth, child: _buildFolderPane()),
        MouseRegion(
          cursor: SystemMouseCursors.resizeColumn,
          child: GestureDetector(
            behavior: HitTestBehavior.opaque,
            onHorizontalDragUpdate: (details) => setState(() {
              _treeWidth = (_treeWidth + details.delta.dx).clamp(220, 360);
            }),
            child: const SizedBox(width: 5, child: VerticalDivider(width: 1)),
          ),
        ),
        Expanded(child: _buildDesktopContent()),
      ],
    );
  }

  Widget _buildSearchField() => SizedBox(
    height: 34,
    child: TextField(
      controller: _searchController,
      onChanged: (value) => setState(() => _query = value),
      decoration: const InputDecoration(
        hintText: '搜索当前 Workspace',
        prefixIcon: Icon(Icons.search, size: 19),
        contentPadding: EdgeInsets.symmetric(horizontal: 10),
        border: OutlineInputBorder(borderSide: BorderSide.none),
        filled: true,
      ),
    ),
  );

  Widget _buildEntryActions() => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      PopupMenuButton<EntryType>(
        tooltip: '新增条目',
        onSelected: _addEntry,
        itemBuilder: (_) => const [
          PopupMenuItem(value: EntryType.login, child: Text('登录密码')),
          PopupMenuItem(value: EntryType.otp, child: Text('OTP')),
          PopupMenuItem(value: EntryType.recoveryCodes, child: Text('恢复码')),
          PopupMenuItem(value: EntryType.secureNote, child: Text('安全笔记')),
        ],
        child: const Padding(
          padding: EdgeInsets.symmetric(horizontal: 8),
          child: Row(children: [Icon(Icons.add, size: 19), Text('新增')]),
        ),
      ),
      TextButton.icon(
        onPressed: _importOtp,
        icon: const Icon(Icons.qr_code_2, size: 19),
        label: const Text('导入 OTP'),
      ),
      IconButton(
        onPressed: _productivityService == null ? null : _showPasswordGenerator,
        tooltip: '密码生成器',
        icon: const Icon(Icons.password_outlined),
      ),
    ],
  );

  Widget _buildSyncStatus() {
    final workspace = _selected;
    if (workspace == null) return const SizedBox.shrink();
    final state =
        _syncStates[workspace.id] ??
        (workspace.sync.configured
            ? workspace.sync.passwordStored
                  ? _WorkspaceSyncState.pending
                  : _WorkspaceSyncState.credentialsNeeded
            : _WorkspaceSyncState.unconfigured);
    final (icon, label) = switch (state) {
      _WorkspaceSyncState.unconfigured => (Icons.cloud_off_outlined, '同步未配置'),
      _WorkspaceSyncState.credentialsNeeded => (
        Icons.key_off_outlined,
        '同步需要凭据',
      ),
      _WorkspaceSyncState.waitingNetwork => (
        Icons.signal_wifi_connected_no_internet_4_outlined,
        '等待可用网络',
      ),
      _WorkspaceSyncState.pending => (Icons.schedule_outlined, '同步待处理'),
      _WorkspaceSyncState.syncing => (Icons.sync, '正在同步'),
      _WorkspaceSyncState.synced => (Icons.cloud_done_outlined, '已同步'),
      _WorkspaceSyncState.failed => (Icons.sync_problem_outlined, '同步失败，将自动重试'),
    };
    return IconButton(
      onPressed: _productivityService == null ? null : _openSettings,
      tooltip: label,
      icon: Icon(icon, size: 20),
    );
  }

  List<VaultEntryItem> _visibleEntries() {
    final query = _query.trim().toLowerCase();
    final selectedGroup = _selectedGroupId;
    final scopedGroups = selectedGroup == null
        ? <String>{}
        : _descendantGroupIds(selectedGroup);
    final selectedIsRecycle =
        selectedGroup != null && _isInsideRecycle(selectedGroup);
    final visible =
        _selectedEntries.where((entry) {
          final typeMatches = switch (_section) {
            _VaultSection.passwords =>
              entry.hasPassword || entry.type == EntryType.login,
            _VaultSection.otp => entry.hasOtp,
            _VaultSection.other =>
              entry.type == EntryType.recoveryCodes ||
                  entry.type == EntryType.secureNote,
          };
          final folderMatches = query.isNotEmpty
              ? entry.isInRecycleBin == selectedIsRecycle
              : (scopedGroups.isEmpty ||
                        scopedGroups.contains(entry.groupId)) &&
                    entry.isInRecycleBin == selectedIsRecycle;
          final textMatches =
              query.isEmpty ||
              entry.title.toLowerCase().contains(query) ||
              entry.username.toLowerCase().contains(query) ||
              entry.url.toLowerCase().contains(query) ||
              entry.tags.any((tag) => tag.toLowerCase().contains(query));
          final smartMatches = switch (_smartFilter) {
            _SmartFilter.none => true,
            _SmartFilter.favorites => entry.isFavorite,
            _SmartFilter.recent =>
              entry.modifiedAtUnixMs >
                  DateTime.now()
                      .subtract(const Duration(days: 30))
                      .millisecondsSinceEpoch,
          };
          final tagMatches =
              _selectedTag == null || entry.tags.contains(_selectedTag);
          return typeMatches &&
              folderMatches &&
              textMatches &&
              smartMatches &&
              tagMatches;
        }).toList()..sort(
          (a, b) => a.title.toLowerCase().compareTo(b.title.toLowerCase()),
        );
    return visible;
  }

  Set<String> _descendantGroupIds(String rootId) {
    final groups = _selectedContent?.groups ?? const <VaultGroupItem>[];
    final result = <String>{rootId};
    var changed = true;
    while (changed) {
      changed = false;
      for (final group in groups) {
        if (group.parentId != null &&
            result.contains(group.parentId) &&
            result.add(group.id)) {
          changed = true;
        }
      }
    }
    return result;
  }

  Widget _buildFolderPane() {
    final content = _selectedContent;
    if (content == null) return const SizedBox();
    final root = content.groups.where((group) => group.isRoot).firstOrNull;
    return ColoredBox(
      color: Theme.of(context).colorScheme.surfaceContainerLow,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(14, 12, 8, 6),
            child: Row(
              children: [
                Text('文件夹', style: Theme.of(context).textTheme.labelLarge),
                const Spacer(),
                IconButton(
                  onPressed: _structuredService == null ? null : _createFolder,
                  tooltip: '新建文件夹',
                  icon: const Icon(Icons.create_new_folder_outlined, size: 19),
                ),
              ],
            ),
          ),
          Expanded(
            child: ListView(
              padding: const EdgeInsets.symmetric(horizontal: 6),
              children: [if (root != null) ..._folderRows(root, 0)],
            ),
          ),
          const Divider(height: 1),
          const Padding(
            padding: EdgeInsets.fromLTRB(14, 10, 14, 4),
            child: Text('搜索与标签', style: TextStyle(fontSize: 12)),
          ),
          _folderShortcut(Icons.list_alt_outlined, '所有条目', () {
            _selectGroup(content.rootGroupId);
          }),
          _folderShortcut(Icons.star_outline, '收藏', () {
            setState(() {
              _selectedGroups[_selectedId!] = content.rootGroupId;
              _smartFilter = _SmartFilter.favorites;
              _selectedTag = null;
            });
          }),
          _folderShortcut(Icons.history, '最近修改', () {
            setState(() {
              _selectedGroups[_selectedId!] = content.rootGroupId;
              _smartFilter = _SmartFilter.recent;
              _selectedTag = null;
            });
          }),
          _folderShortcut(
            Icons.health_and_safety_outlined,
            '密码健康',
            _openSettings,
          ),
          if (_selectedEntries
              .expand((entry) => entry.tags)
              .toSet()
              .isNotEmpty) ...[
            const Padding(
              padding: EdgeInsets.fromLTRB(14, 10, 14, 4),
              child: Text('标签', style: TextStyle(fontSize: 12)),
            ),
            for (final tag
                in (_selectedEntries
                    .expand((entry) => entry.tags)
                    .toSet()
                    .toList()
                  ..sort()))
              _folderShortcut(Icons.sell_outlined, tag, () {
                setState(() {
                  _selectedGroups[_selectedId!] = content.rootGroupId;
                  _selectedTag = tag;
                  _smartFilter = _SmartFilter.none;
                });
              }),
          ],
          const SizedBox(height: 8),
        ],
      ),
    );
  }

  List<Widget> _folderRows(VaultGroupItem group, int depth) {
    final content = _selectedContent!;
    final children = content.groups
        .where((item) => item.parentId == group.id)
        .toList(growable: false);
    final selected = _selectedGroupId == group.id;
    final inRecycle = _isInsideRecycle(group.id);
    return [
      Material(
        color: selected
            ? Theme.of(context).colorScheme.secondaryContainer
            : Colors.transparent,
        borderRadius: BorderRadius.circular(7),
        child: InkWell(
          onTap: () => _selectGroup(group.id),
          borderRadius: BorderRadius.circular(7),
          child: SizedBox(
            height: 36,
            child: Row(
              children: [
                SizedBox(width: 8.0 + depth * 16),
                _vaultIcon(
                  group.icon,
                  group.isRecycleBin
                      ? Icons.delete_outline
                      : group.isRoot
                      ? Icons.folder_special_outlined
                      : Icons.folder_outlined,
                  19,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(group.name, overflow: TextOverflow.ellipsis),
                ),
                if (!group.isRoot && !group.isRecycleBin)
                  PopupMenuButton<String>(
                    padding: EdgeInsets.zero,
                    iconSize: 17,
                    onSelected: (action) {
                      if (action == 'new') _createFolder(group.id);
                      if (action == 'rename') _renameFolder(group);
                      if (action == 'move') _moveFolderTo(group);
                      if (action == 'icon') _chooseFolderIcon(group);
                      if (action == 'trash') _trashFolder(group);
                      if (action == 'restore') _restoreFolder(group);
                      if (action == 'delete') _deleteFolderPermanently(group);
                    },
                    itemBuilder: (_) => inRecycle
                        ? const [
                            PopupMenuItem(value: 'restore', child: Text('恢复')),
                            PopupMenuItem(value: 'delete', child: Text('永久删除')),
                          ]
                        : const [
                            PopupMenuItem(value: 'new', child: Text('新建子文件夹')),
                            PopupMenuItem(value: 'rename', child: Text('重命名')),
                            PopupMenuItem(value: 'move', child: Text('移动到…')),
                            PopupMenuItem(value: 'icon', child: Text('设置图标')),
                            PopupMenuItem(value: 'trash', child: Text('移至回收站')),
                          ],
                  ),
              ],
            ),
          ),
        ),
      ),
      for (final child in children) ..._folderRows(child, depth + 1),
      if (group.isRecycleBin && selected)
        TextButton.icon(
          onPressed: _emptyRecycleBin,
          icon: const Icon(Icons.delete_sweep_outlined, size: 18),
          label: const Text('清空回收站'),
        ),
    ];
  }

  Widget _folderShortcut(IconData icon, String label, VoidCallback onTap) =>
      ListTile(
        dense: true,
        visualDensity: VisualDensity.compact,
        leading: Icon(icon, size: 18),
        title: Text(label),
        onTap: onTap,
      );

  Widget _buildDesktopContent() => Column(
    children: [
      _buildSectionBar(),
      const Divider(height: 1),
      Expanded(
        child: LayoutBuilder(
          builder: (context, constraints) {
            final listHeight = (constraints.maxHeight * _listFraction).clamp(
              180.0,
              constraints.maxHeight - 150,
            );
            return Column(
              children: [
                SizedBox(height: listHeight, child: _buildEntryTable()),
                MouseRegion(
                  cursor: SystemMouseCursors.resizeRow,
                  child: GestureDetector(
                    behavior: HitTestBehavior.opaque,
                    onVerticalDragUpdate: (details) => setState(() {
                      _listFraction =
                          (_listFraction +
                                  details.delta.dy / constraints.maxHeight)
                              .clamp(.3, .78);
                    }),
                    child: const SizedBox(
                      height: 7,
                      child: Divider(height: 1, thickness: 1),
                    ),
                  ),
                ),
                Expanded(child: _buildDetailPane()),
              ],
            );
          },
        ),
      ),
    ],
  );

  void _setSection(_VaultSection section) {
    _hidePassword();
    setState(() {
      _section = section;
      _selectedEntryId = null;
    });
  }

  Widget _sectionChoices() => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      for (final section in _VaultSection.values)
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 2),
          child: ChoiceChip(
            label: Text(switch (section) {
              _VaultSection.passwords => '密码',
              _VaultSection.otp => 'OTP',
              _VaultSection.other => '其他',
            }),
            selected: _section == section,
            onSelected: (_) => _setSection(section),
            showCheckmark: false,
            visualDensity: VisualDensity.compact,
          ),
        ),
    ],
  );

  Widget _buildSectionBar({bool mobile = false}) => SizedBox(
    height: mobile ? 88 : 48,
    child: mobile
        ? Column(
            children: [
              SizedBox(
                height: 42,
                child: Row(
                  children: [
                    IconButton(
                      tooltip: '选择文件夹',
                      onPressed: _showMobileFolders,
                      icon: const Icon(Icons.folder_open_outlined, size: 20),
                    ),
                    Expanded(child: Center(child: _sectionChoices())),
                    const SizedBox(width: 48),
                  ],
                ),
              ),
              SizedBox(height: 44, child: _buildEntryActions()),
            ],
          )
        : Row(
            children: [
              const SizedBox(width: 8),
              _sectionChoices(),
              const Spacer(),
              _buildEntryActions(),
              const SizedBox(width: 6),
            ],
          ),
  );

  Future<void> _showMobileFolders() async {
    final content = _selectedContent;
    if (content == null) return;
    final selected = await showModalBottomSheet<String>(
      context: context,
      showDragHandle: true,
      builder: (context) => SafeArea(
        child: ListView(
          children: [
            const ListTile(title: Text('选择文件夹')),
            for (final group in content.groups)
              ListTile(
                leading: Icon(
                  group.isRecycleBin
                      ? Icons.delete_outline
                      : Icons.folder_outlined,
                ),
                title: Text(_groupPath(group.id)),
                selected: group.id == _selectedGroupId,
                onTap: () => Navigator.pop(context, group.id),
              ),
          ],
        ),
      ),
    );
    if (selected != null) _selectGroup(selected);
  }

  Widget _buildEntryTable() {
    final visible = _visibleEntries();
    if (visible.isEmpty) {
      return Center(
        child: Text(_query.trim().isEmpty ? '这个 Workspace 还是空的' : '没有匹配的条目'),
      );
    }
    return Column(
      children: [
        Container(
          height: 36,
          color: Theme.of(context).colorScheme.surfaceContainer,
          child: const Row(
            children: [
              SizedBox(width: 42),
              Expanded(flex: 3, child: Text('标题')),
              Expanded(flex: 3, child: Text('用户名')),
              Expanded(flex: 3, child: Text('URL')),
              SizedBox(width: 150, child: Text('修改时间')),
              SizedBox(width: 42),
            ],
          ),
        ),
        Expanded(
          child: ListView.builder(
            itemCount: visible.length,
            itemExtent: 39,
            itemBuilder: (_, index) => _entryRow(visible[index]),
          ),
        ),
      ],
    );
  }

  Widget _entryRow(VaultEntryItem item) {
    final selected = item.id == _selectedEntryId;
    return Material(
      color: selected
          ? Theme.of(context).colorScheme.secondaryContainer
          : indexColor(item),
      child: InkWell(
        onTap: () => _selectEntry(item),
        child: Row(
          children: [
            SizedBox(
              width: 42,
              child: Center(
                child: _vaultIcon(item.icon, _iconFor(item.type), 19),
              ),
            ),
            Expanded(
              flex: 3,
              child: Row(
                children: [
                  if (item.isFavorite)
                    const Padding(
                      padding: EdgeInsets.only(right: 5),
                      child: Icon(Icons.star, size: 15),
                    ),
                  Expanded(
                    child: Text(item.title, overflow: TextOverflow.ellipsis),
                  ),
                ],
              ),
            ),
            Expanded(
              flex: 3,
              child: Text(item.username, overflow: TextOverflow.ellipsis),
            ),
            Expanded(
              flex: 3,
              child: Text(item.url, overflow: TextOverflow.ellipsis),
            ),
            SizedBox(
              width: 150,
              child: Text(_formatModified(item.modifiedAtUnixMs)),
            ),
            SizedBox(width: 42, child: _entryMenu(item)),
          ],
        ),
      ),
    );
  }

  Color indexColor(VaultEntryItem item) => Colors.transparent;

  String _formatModified(int milliseconds) {
    if (milliseconds <= 0) return '—';
    final value = DateTime.fromMillisecondsSinceEpoch(milliseconds);
    String two(int number) => number.toString().padLeft(2, '0');
    return '${value.year}-${two(value.month)}-${two(value.day)} '
        '${two(value.hour)}:${two(value.minute)}';
  }

  Widget _entryMenu(VaultEntryItem item) => PopupMenuButton<String>(
    padding: EdgeInsets.zero,
    onSelected: (action) {
      if (action == 'edit') _editEntry(item);
      if (action == 'move') _moveEntryTo(item);
      if (action == 'notes') _reveal(item, true);
      if (action == 'delete') _deleteEntry(item);
      if (action == 'restore') _restoreEntry(item);
    },
    itemBuilder: (_) => item.isInRecycleBin
        ? const [
            PopupMenuItem(value: 'restore', child: Text('恢复')),
            PopupMenuItem(value: 'delete', child: Text('永久删除')),
          ]
        : const [
            PopupMenuItem(value: 'edit', child: Text('编辑')),
            PopupMenuItem(value: 'move', child: Text('移动到…')),
            PopupMenuItem(value: 'notes', child: Text('显示受保护内容')),
            PopupMenuItem(value: 'delete', child: Text('移至回收站')),
          ],
  );

  Widget _buildDetailPane() {
    final item = _selectedEntry;
    if (item == null) {
      return const Center(child: Text('选择一个条目查看详情'));
    }
    final otp = _codes[item.id];
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(20, 14, 20, 24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              CircleAvatar(
                child: _vaultIcon(item.icon, _iconFor(item.type), 22),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      item.title,
                      style: Theme.of(context).textTheme.titleLarge,
                    ),
                    Text(
                      _groupPath(item.groupId),
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ),
              ),
              IconButton(
                tooltip: item.isFavorite ? '取消收藏' : '收藏',
                onPressed: _productivityService == null
                    ? null
                    : () => _toggleFavorite(item),
                icon: Icon(item.isFavorite ? Icons.star : Icons.star_border),
              ),
              IconButton(
                onPressed: () => _editEntry(item),
                icon: const Icon(Icons.edit_outlined),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Wrap(
            spacing: 40,
            runSpacing: 14,
            children: [
              if (item.username.isNotEmpty)
                _detailField('用户名', item.username, copy: true),
              if (item.url.isNotEmpty)
                _detailField('URL', item.url, copy: true),
              if (item.hasPassword)
                _detailField(
                  '密码',
                  _revealedPassword ?? '••••••••••••',
                  action: IconButton(
                    tooltip: _revealedPassword == null ? '显示密码' : '隐藏密码',
                    onPressed: () => _togglePassword(item),
                    icon: Icon(
                      _revealedPassword == null
                          ? Icons.visibility_outlined
                          : Icons.visibility_off_outlined,
                    ),
                  ),
                  copy: _revealedPassword != null,
                ),
              if (otp != null) _detailField('动态验证码', otp.code, copy: true),
            ],
          ),
          if (item.tags.isNotEmpty) ...[
            const SizedBox(height: 18),
            Wrap(
              spacing: 6,
              children: item.tags.map((tag) => Chip(label: Text(tag))).toList(),
            ),
          ],
          const SizedBox(height: 18),
          Row(
            children: [
              Text('附件', style: Theme.of(context).textTheme.titleMedium),
              const Spacer(),
              TextButton.icon(
                onPressed: _productivityService == null
                    ? null
                    : () => _addAttachment(item),
                icon: const Icon(Icons.attach_file, size: 18),
                label: const Text('添加附件'),
              ),
            ],
          ),
          if (item.attachments.isEmpty)
            Text('暂无附件', style: Theme.of(context).textTheme.bodySmall)
          else
            for (final attachment in item.attachments)
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(Icons.insert_drive_file_outlined),
                title: Text(attachment.name),
                subtitle: Text(_formatBytes(attachment.size)),
                trailing: PopupMenuButton<String>(
                  onSelected: (action) {
                    if (action == 'export') {
                      _exportAttachment(item, attachment);
                    } else if (action == 'rename') {
                      _renameAttachment(item, attachment);
                    } else if (action == 'delete') {
                      _removeAttachment(item, attachment);
                    }
                  },
                  itemBuilder: (_) => const [
                    PopupMenuItem(value: 'export', child: Text('导出')),
                    PopupMenuItem(value: 'rename', child: Text('重命名')),
                    PopupMenuItem(value: 'delete', child: Text('删除')),
                  ],
                ),
              ),
        ],
      ),
    );
  }

  Widget _detailField(
    String label,
    String value, {
    bool copy = false,
    Widget? action,
  }) => SizedBox(
    width: 360,
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: Theme.of(context).textTheme.labelMedium),
        Row(
          children: [
            Expanded(child: SelectableText(value)),
            action ?? const SizedBox.shrink(),
            if (copy)
              IconButton(
                tooltip: '复制',
                onPressed: () => _copy(value),
                icon: const Icon(Icons.copy_outlined, size: 18),
              ),
          ],
        ),
      ],
    ),
  );

  Widget _vaultIcon(VaultIconItem icon, IconData fallback, double size) {
    if (icon.type == VaultIconType.builtIn && icon.builtInId != null) {
      return Icon(_keepassIcon(icon.builtInId!), size: size);
    }
    final customId = icon.customId;
    final handle = _selectedHandle;
    final service = _productivityService;
    if (icon.type == VaultIconType.custom &&
        customId != null &&
        handle != null &&
        service != null) {
      final key = '$handle:$customId';
      final load = _customIconLoads.putIfAbsent(
        key,
        () => service.loadCustomIcon(handle, customId),
      );
      return FutureBuilder<Uint8List>(
        future: load,
        builder: (context, snapshot) {
          final bytes = snapshot.data;
          if (bytes == null) return Icon(fallback, size: size);
          return Image.memory(
            bytes,
            width: size,
            height: size,
            fit: BoxFit.contain,
            errorBuilder: (_, _, _) => Icon(fallback, size: size),
          );
        },
      );
    }
    return Icon(fallback, size: size);
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KiB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MiB';
  }

  Widget _buildMobileWorkspace() {
    final workspace = _selected;
    if (workspace == null) return const SizedBox();
    if (_selectedHandle == null) {
      return _LockedWorkspace(
        workspace: workspace,
        onUnlock: _unlock,
        onQuickUnlock: workspace.quickUnlockEnabled ? _quickUnlock : null,
      );
    }
    final visible = _visibleEntries();
    return Column(
      children: [
        _buildSectionBar(mobile: true),
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 2, 12, 8),
          child: _buildSearchField(),
        ),
        Expanded(
          child: visible.isEmpty
              ? const Center(child: Text('这个 Workspace 还是空的'))
              : ListView.separated(
                  padding: const EdgeInsets.all(12),
                  itemCount: visible.length,
                  separatorBuilder: (_, _) => const Divider(height: 1),
                  itemBuilder: (_, index) {
                    final item = visible[index];
                    final otp = _codes[item.id];
                    return ListTile(
                      leading: _vaultIcon(item.icon, _iconFor(item.type), 24),
                      title: Text(item.title),
                      subtitle: Text(
                        item.username.isEmpty
                            ? _labelFor(item.type)
                            : item.username,
                      ),
                      trailing: otp == null
                          ? _entryMenu(item)
                          : Text(
                              otp.code,
                              style: const TextStyle(letterSpacing: 2),
                            ),
                      onTap: () {
                        _selectEntry(item);
                        Navigator.of(context).push(
                          MaterialPageRoute<void>(
                            builder: (_) => Scaffold(
                              appBar: AppBar(title: Text(item.title)),
                              body: _buildDetailPane(),
                            ),
                          ),
                        );
                      },
                    );
                  },
                ),
        ),
      ],
    );
  }
}

IconData _keepassIcon(int id) {
  const icons = <IconData>[
    Icons.key,
    Icons.public,
    Icons.warning_amber,
    Icons.dns_outlined,
    Icons.push_pin_outlined,
    Icons.chat_bubble_outline,
    Icons.grid_view,
    Icons.edit_note,
    Icons.lan_outlined,
    Icons.badge_outlined,
    Icons.description_outlined,
    Icons.camera_alt_outlined,
    Icons.wifi,
    Icons.link,
    Icons.battery_full,
    Icons.scanner_outlined,
    Icons.bookmark_outline,
    Icons.album_outlined,
    Icons.monitor_outlined,
    Icons.email_outlined,
    Icons.settings,
    Icons.content_paste,
    Icons.description,
    Icons.bolt,
  ];
  return icons[id % icons.length];
}

class _CreateFolderRequest {
  const _CreateFolderRequest({required this.name, required this.iconId});
  final String name;
  final int? iconId;
}

class _CreateFolderDialog extends StatefulWidget {
  const _CreateFolderDialog();

  @override
  State<_CreateFolderDialog> createState() => _CreateFolderDialogState();
}

class _CreateFolderDialogState extends State<_CreateFolderDialog> {
  final name = TextEditingController();
  int? iconId;

  @override
  void dispose() {
    name.dispose();
    super.dispose();
  }

  void _submit() {
    final value = name.text.trim();
    if (value.isEmpty) return;
    Navigator.pop(context, _CreateFolderRequest(name: value, iconId: iconId));
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('新建文件夹'),
    content: SizedBox(
      width: 470,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          TextField(
            controller: name,
            autofocus: true,
            decoration: const InputDecoration(labelText: '名称'),
            onSubmitted: (_) => _submit(),
          ),
          const SizedBox(height: 18),
          Text('图标', style: Theme.of(context).textTheme.labelLarge),
          const SizedBox(height: 8),
          SizedBox(
            height: 164,
            child: GridView.count(
              crossAxisCount: 8,
              mainAxisSpacing: 8,
              crossAxisSpacing: 8,
              children: [
                _iconChoice(
                  value: null,
                  icon: Icons.folder_outlined,
                  tooltip: '默认文件夹图标',
                ),
                for (var id = 0; id < 24; id++)
                  _iconChoice(
                    value: id,
                    icon: _keepassIcon(id),
                    tooltip: 'KeePass 图标 ${id + 1}',
                  ),
              ],
            ),
          ),
        ],
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('取消'),
      ),
      FilledButton(onPressed: _submit, child: const Text('创建')),
    ],
  );

  Widget _iconChoice({
    required int? value,
    required IconData icon,
    required String tooltip,
  }) {
    final selected = iconId == value;
    return Tooltip(
      message: tooltip,
      child: InkWell(
        onTap: () => setState(() => iconId = value),
        borderRadius: BorderRadius.circular(8),
        child: DecoratedBox(
          decoration: BoxDecoration(
            color: selected
                ? Theme.of(context).colorScheme.secondaryContainer
                : null,
            border: selected
                ? Border.all(color: Theme.of(context).colorScheme.primary)
                : null,
            borderRadius: BorderRadius.circular(8),
          ),
          child: Icon(icon),
        ),
      ),
    );
  }
}

class _FolderIconDialog extends StatelessWidget {
  const _FolderIconDialog({required this.current});
  final int? current;

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('设置文件夹图标'),
    content: SizedBox(
      width: 460,
      child: GridView.count(
        shrinkWrap: true,
        crossAxisCount: 8,
        mainAxisSpacing: 8,
        crossAxisSpacing: 8,
        children: [
          InkWell(
            onTap: () => Navigator.pop(context, -1),
            borderRadius: BorderRadius.circular(8),
            child: const Tooltip(
              message: '默认文件夹图标',
              child: Icon(Icons.folder_outlined),
            ),
          ),
          for (var id = 0; id < 24; id++)
            InkWell(
              onTap: () => Navigator.pop(context, id),
              borderRadius: BorderRadius.circular(8),
              child: DecoratedBox(
                decoration: BoxDecoration(
                  border: current == id
                      ? Border.all(
                          color: Theme.of(context).colorScheme.primary,
                          width: 2,
                        )
                      : null,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(_keepassIcon(id)),
              ),
            ),
        ],
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context, -2),
        child: const Text('取消'),
      ),
    ],
  );
}

class _PasswordGeneratorDialog extends StatefulWidget {
  const _PasswordGeneratorDialog({required this.service});
  final ProductivityVaultService service;

  @override
  State<_PasswordGeneratorDialog> createState() =>
      _PasswordGeneratorDialogState();
}

class _PasswordGeneratorDialogState extends State<_PasswordGeneratorDialog> {
  bool passphrase = false;
  double length = 20;
  bool lowercase = true;
  bool uppercase = true;
  bool digits = true;
  bool symbols = true;
  bool excludeAmbiguous = true;
  bool capitalize = false;
  bool includeNumber = false;
  GeneratedPassword? generated;
  bool busy = false;

  @override
  void initState() {
    super.initState();
    _generate();
  }

  Future<void> _generate() async {
    setState(() => busy = true);
    try {
      generated = passphrase
          ? await widget.service.generatePassphrase(
              wordCount: length.round().clamp(4, 12),
              capitalize: capitalize,
              includeNumber: includeNumber,
            )
          : await widget.service.generateRandomPassword(
              length: length.round(),
              lowercase: lowercase,
              uppercase: uppercase,
              digits: digits,
              symbols: symbols,
              excludeAmbiguous: excludeAmbiguous,
            );
    } on Object {
      generated = null;
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('密码生成器'),
    content: SizedBox(
      width: 520,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          SegmentedButton<bool>(
            segments: const [
              ButtonSegment(value: false, label: Text('随机密码')),
              ButtonSegment(value: true, label: Text('口令短语')),
            ],
            selected: {passphrase},
            onSelectionChanged: (value) {
              setState(() {
                passphrase = value.first;
                length = passphrase ? 6 : 20;
              });
              _generate();
            },
          ),
          const SizedBox(height: 18),
          SelectableText(
            generated?.value ?? (busy ? '正在生成…' : '请选择有效选项'),
            style: Theme.of(context).textTheme.titleMedium,
          ),
          if (generated != null) Text('估算熵：${generated!.entropyBits} bits'),
          const SizedBox(height: 12),
          Row(
            children: [
              Text(
                passphrase ? '单词数 ${length.round()}' : '长度 ${length.round()}',
              ),
              Expanded(
                child: Slider(
                  min: passphrase ? 4 : 12,
                  max: passphrase ? 12 : 128,
                  divisions: passphrase ? 8 : 116,
                  value: length,
                  onChanged: (value) => setState(() => length = value),
                  onChangeEnd: (_) => _generate(),
                ),
              ),
            ],
          ),
          if (passphrase) ...[
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('单词首字母大写'),
              value: capitalize,
              onChanged: (value) {
                setState(() => capitalize = value);
                _generate();
              },
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('附加数字'),
              value: includeNumber,
              onChanged: (value) {
                setState(() => includeNumber = value);
                _generate();
              },
            ),
          ] else ...[
            Wrap(
              spacing: 8,
              children: [
                FilterChip(
                  label: const Text('a-z'),
                  selected: lowercase,
                  onSelected: (value) {
                    setState(() => lowercase = value);
                    _generate();
                  },
                ),
                FilterChip(
                  label: const Text('A-Z'),
                  selected: uppercase,
                  onSelected: (value) {
                    setState(() => uppercase = value);
                    _generate();
                  },
                ),
                FilterChip(
                  label: const Text('0-9'),
                  selected: digits,
                  onSelected: (value) {
                    setState(() => digits = value);
                    _generate();
                  },
                ),
                FilterChip(
                  label: const Text('符号'),
                  selected: symbols,
                  onSelected: (value) {
                    setState(() => symbols = value);
                    _generate();
                  },
                ),
                FilterChip(
                  label: const Text('排除易混淆字符'),
                  selected: excludeAmbiguous,
                  onSelected: (value) {
                    setState(() => excludeAmbiguous = value);
                    _generate();
                  },
                ),
              ],
            ),
          ],
        ],
      ),
    ),
    actions: [
      TextButton(onPressed: _generate, child: const Text('重新生成')),
      FilledButton.icon(
        onPressed: generated == null
            ? null
            : () => Navigator.pop(context, generated!.value),
        icon: const Icon(Icons.copy_outlined),
        label: const Text('复制并关闭'),
      ),
    ],
  );
}

class _LockedWorkspace extends StatelessWidget {
  const _LockedWorkspace({
    required this.workspace,
    required this.onUnlock,
    this.onQuickUnlock,
  });

  final WorkspaceInfo workspace;
  final VoidCallback onUnlock;
  final VoidCallback? onQuickUnlock;

  @override
  Widget build(BuildContext context) => Center(
    child: Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        const Icon(Icons.lock_outline, size: 64),
        const SizedBox(height: 16),
        Text(
          '${workspace.name} 已锁定',
          style: Theme.of(context).textTheme.titleLarge,
        ),
        const SizedBox(height: 8),
        const Text('主密码不会保存在 Workspace 元数据中。'),
        const SizedBox(height: 20),
        FilledButton.icon(
          onPressed: onUnlock,
          icon: const Icon(Icons.lock_open),
          label: const Text('解锁'),
        ),
        if (onQuickUnlock != null) ...[
          const SizedBox(height: 12),
          OutlinedButton.icon(
            onPressed: onQuickUnlock,
            icon: const Icon(Icons.fingerprint),
            label: const Text('生物识别快速解锁'),
          ),
        ],
      ],
    ),
  );
}

class _SecuritySettingsResult {
  const _SecuritySettingsResult({
    required this.autoLockSeconds,
    required this.quickUnlockEnabled,
  });
  final int autoLockSeconds;
  final bool quickUnlockEnabled;
}

class _SecuritySettingsDialog extends StatefulWidget {
  const _SecuritySettingsDialog({
    required this.workspace,
    required this.unlocked,
    required this.initialAutoLockSeconds,
  });
  final WorkspaceInfo workspace;
  final bool unlocked;
  final int initialAutoLockSeconds;

  @override
  State<_SecuritySettingsDialog> createState() =>
      _SecuritySettingsDialogState();
}

class _SecuritySettingsDialogState extends State<_SecuritySettingsDialog> {
  late int timeout = widget.initialAutoLockSeconds;
  late bool quickUnlock = widget.workspace.quickUnlockEnabled;

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('安全设置'),
    content: SizedBox(
      width: 460,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          DropdownButtonFormField<int>(
            initialValue: timeout,
            decoration: const InputDecoration(labelText: '进入后台后自动锁定'),
            items: const [
              DropdownMenuItem(value: 0, child: Text('立即')),
              DropdownMenuItem(value: 30, child: Text('30 秒')),
              DropdownMenuItem(value: 60, child: Text('1 分钟')),
              DropdownMenuItem(value: 300, child: Text('5 分钟（默认）')),
              DropdownMenuItem(value: 900, child: Text('15 分钟')),
            ],
            onChanged: (value) => setState(() => timeout = value!),
          ),
          const SizedBox(height: 12),
          SwitchListTile(
            contentPadding: EdgeInsets.zero,
            title: const Text('强生物识别快速解锁'),
            subtitle: Text(
              widget.unlocked
                  ? '默认关闭；密钥仅由 Android Keystore 解封。'
                  : '请先使用主密码解锁此 Workspace。',
            ),
            value: quickUnlock,
            onChanged: widget.unlocked || quickUnlock
                ? (value) => setState(() => quickUnlock = value)
                : null,
          ),
        ],
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('取消'),
      ),
      FilledButton(
        onPressed: () => Navigator.pop(
          context,
          _SecuritySettingsResult(
            autoLockSeconds: timeout,
            quickUnlockEnabled: quickUnlock,
          ),
        ),
        child: const Text('保存'),
      ),
    ],
  );
}

class _QuickUnlockSelectionDialog extends StatefulWidget {
  const _QuickUnlockSelectionDialog({
    required this.workspaces,
    required this.initiallySelectedId,
  });
  final List<WorkspaceInfo> workspaces;
  final String initiallySelectedId;

  @override
  State<_QuickUnlockSelectionDialog> createState() =>
      _QuickUnlockSelectionDialogState();
}

class _QuickUnlockSelectionDialogState
    extends State<_QuickUnlockSelectionDialog> {
  late final selected = <String>{
    if (widget.workspaces.any((item) => item.id == widget.initiallySelectedId))
      widget.initiallySelectedId
    else
      widget.workspaces.first.id,
  };

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('选择要快速解锁的 Workspace'),
    content: SizedBox(
      width: 440,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          for (final workspace in widget.workspaces)
            CheckboxListTile(
              value: selected.contains(workspace.id),
              title: Text(workspace.name),
              onChanged: (value) => setState(() {
                if (value ?? false) {
                  selected.add(workspace.id);
                } else {
                  selected.remove(workspace.id);
                }
              }),
            ),
        ],
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('取消'),
      ),
      FilledButton(
        onPressed: selected.isEmpty
            ? null
            : () => Navigator.pop(
                context,
                widget.workspaces
                    .where((item) => selected.contains(item.id))
                    .toList(growable: false),
              ),
        child: const Text('验证并解锁'),
      ),
    ],
  );
}

class _CreateWorkspaceRequest {
  const _CreateWorkspaceRequest(this.name, this.password);
  final String name;
  final String password;
}

class _CreateWorkspaceDialog extends StatefulWidget {
  const _CreateWorkspaceDialog();
  @override
  State<_CreateWorkspaceDialog> createState() => _CreateWorkspaceDialogState();
}

class _CreateWorkspaceDialogState extends State<_CreateWorkspaceDialog> {
  final name = TextEditingController();
  final password = TextEditingController();
  final confirm = TextEditingController();
  String? error;

  @override
  void dispose() {
    name.dispose();
    password.clear();
    password.dispose();
    confirm.clear();
    confirm.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('新建 Workspace'),
    content: SizedBox(
      width: 440,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: name,
            autofocus: true,
            decoration: const InputDecoration(labelText: '名称'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: password,
            obscureText: true,
            autocorrect: false,
            enableSuggestions: false,
            decoration: const InputDecoration(labelText: '主密码（至少 12 个字符）'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: confirm,
            obscureText: true,
            autocorrect: false,
            enableSuggestions: false,
            decoration: InputDecoration(labelText: '确认主密码', errorText: error),
          ),
        ],
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('取消'),
      ),
      FilledButton(
        onPressed: () {
          if (name.text.trim().isEmpty ||
              password.text.characters.length < 12 ||
              password.text != confirm.text) {
            setState(() => error = '请填写名称，且两次输入的主密码一致并至少 12 个字符。');
            return;
          }
          Navigator.pop(
            context,
            _CreateWorkspaceRequest(name.text.trim(), password.text),
          );
        },
        child: const Text('创建'),
      ),
    ],
  );
}

class _ImportWorkspaceRequest {
  const _ImportWorkspaceRequest(this.name, this.path, this.password);
  final String name;
  final String path;
  final String password;
}

class _ImportWorkspaceDialog extends StatefulWidget {
  const _ImportWorkspaceDialog({required this.initialPath});
  final String initialPath;
  @override
  State<_ImportWorkspaceDialog> createState() => _ImportWorkspaceDialogState();
}

class _ImportWorkspaceDialogState extends State<_ImportWorkspaceDialog> {
  late final name = TextEditingController(
    text: suggestWorkspaceName(widget.initialPath),
  );
  late final path = TextEditingController(text: widget.initialPath);
  final password = TextEditingController();
  String? error;

  @override
  void dispose() {
    name.dispose();
    path.dispose();
    password.clear();
    password.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('导入现有 KDBX'),
    content: SizedBox(
      width: 520,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: name,
            decoration: const InputDecoration(labelText: 'Workspace 名称'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: path,
            decoration: const InputDecoration(labelText: 'KDBX 文件完整路径'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: password,
            obscureText: true,
            autocorrect: false,
            enableSuggestions: false,
            decoration: const InputDecoration(labelText: '主密码'),
          ),
          if (error != null) ...[
            const SizedBox(height: 12),
            Text(
              error!,
              style: TextStyle(color: Theme.of(context).colorScheme.error),
            ),
          ],
        ],
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('取消'),
      ),
      FilledButton(
        onPressed: () {
          if (path.text.trim().isEmpty) {
            setState(() => error = '请选择一个 KDBX 文件。');
            return;
          }
          Navigator.pop(
            context,
            _ImportWorkspaceRequest(
              name.text.trim(),
              path.text.trim(),
              password.text,
            ),
          );
        },
        child: const Text('导入并解锁'),
      ),
    ],
  );
}

class _PasswordDialog extends StatefulWidget {
  const _PasswordDialog({required this.workspaceName});
  final String workspaceName;
  @override
  State<_PasswordDialog> createState() => _PasswordDialogState();
}

class _PasswordDialogState extends State<_PasswordDialog> {
  final controller = TextEditingController();
  @override
  void dispose() {
    controller.clear();
    controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text('解锁 ${widget.workspaceName}'),
    content: TextField(
      controller: controller,
      autofocus: true,
      obscureText: true,
      autocorrect: false,
      enableSuggestions: false,
      onSubmitted: (value) => Navigator.pop(context, value),
      decoration: const InputDecoration(labelText: '主密码'),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('取消'),
      ),
      FilledButton(
        onPressed: () => Navigator.pop(context, controller.text),
        child: const Text('解锁'),
      ),
    ],
  );
}

class _OtpImportDialog extends StatefulWidget {
  const _OtpImportDialog();
  @override
  State<_OtpImportDialog> createState() => _OtpImportDialogState();
}

class _OtpImportDialogState extends State<_OtpImportDialog> {
  final controller = TextEditingController();
  @override
  void dispose() {
    controller.clear();
    controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('导入 OTP'),
    content: SizedBox(
      width: 500,
      child: TextField(
        controller: controller,
        autofocus: true,
        minLines: 3,
        maxLines: 5,
        decoration: const InputDecoration(labelText: 'otpauth URI'),
      ),
    ),
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: const Text('取消'),
      ),
      FilledButton(
        onPressed: () => Navigator.pop(context, controller.text.trim()),
        child: const Text('导入'),
      ),
    ],
  );
}

class _EntryEditorDialog extends StatefulWidget {
  const _EntryEditorDialog({required this.initialType, this.initial});
  final EntryType initialType;
  final VaultEntryDraft? initial;
  @override
  State<_EntryEditorDialog> createState() => _EntryEditorDialogState();
}

class _EntryEditorDialogState extends State<_EntryEditorDialog> {
  late EntryType type = widget.initial?.type ?? widget.initialType;
  late final title = TextEditingController(text: widget.initial?.title);
  late final username = TextEditingController(text: widget.initial?.username);
  late final password = TextEditingController(text: widget.initial?.password);
  late final url = TextEditingController(text: widget.initial?.url);
  late final notes = TextEditingController(text: widget.initial?.notes);
  late final tags = TextEditingController(
    text: widget.initial?.tags.join(', '),
  );
  final otpUri = TextEditingController();

  @override
  void dispose() {
    title.dispose();
    username.dispose();
    password.clear();
    password.dispose();
    url.dispose();
    notes.clear();
    notes.dispose();
    tags.dispose();
    otpUri.clear();
    otpUri.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final isLogin = type == EntryType.login;
    final isOtp = type == EntryType.otp;
    final isEditingOtp = widget.initial?.preserveExistingOtp ?? false;
    return AlertDialog(
      title: Text(widget.initial == null ? '新增条目' : '编辑条目'),
      content: SizedBox(
        width: 560,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              DropdownButtonFormField<EntryType>(
                initialValue: type,
                decoration: const InputDecoration(labelText: '类型'),
                items: [
                  for (final value in EntryType.values)
                    DropdownMenuItem(
                      value: value,
                      child: Text(_labelFor(value)),
                    ),
                ],
                onChanged: (value) => setState(() => type = value!),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: title,
                autofocus: true,
                decoration: const InputDecoration(labelText: '标题'),
              ),
              if (isLogin || isOtp) ...[
                const SizedBox(height: 12),
                TextField(
                  controller: username,
                  decoration: const InputDecoration(labelText: '账号'),
                ),
              ],
              if (isLogin) ...[
                const SizedBox(height: 12),
                TextField(
                  controller: password,
                  obscureText: true,
                  autocorrect: false,
                  enableSuggestions: false,
                  decoration: const InputDecoration(labelText: '密码'),
                ),
                const SizedBox(height: 12),
                TextField(
                  controller: url,
                  decoration: const InputDecoration(labelText: '网址'),
                ),
              ],
              if (isOtp && !isEditingOtp) ...[
                const SizedBox(height: 12),
                TextField(
                  controller: otpUri,
                  minLines: 2,
                  maxLines: 4,
                  decoration: const InputDecoration(labelText: 'otpauth URI'),
                ),
              ],
              const SizedBox(height: 12),
              TextField(
                controller: notes,
                minLines: 3,
                maxLines: 8,
                decoration: InputDecoration(
                  labelText: type == EntryType.recoveryCodes
                      ? '恢复码（每行一个）'
                      : '受保护内容 / 笔记',
                ),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: tags,
                decoration: const InputDecoration(labelText: '标签（逗号分隔）'),
              ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: const Text('取消'),
        ),
        FilledButton(
          onPressed: () {
            if (title.text.trim().isEmpty) return;
            Navigator.pop(
              context,
              VaultEntryDraft(
                type: type,
                title: title.text.trim(),
                username: username.text,
                password: password.text,
                url: url.text,
                notes: notes.text,
                tags: tags.text
                    .split(',')
                    .map((tag) => tag.trim())
                    .where((tag) => tag.isNotEmpty)
                    .toList(),
                otpUri: otpUri.text.trim().isEmpty ? null : otpUri.text.trim(),
                preserveExistingOtp: isEditingOtp,
              ),
            );
          },
          child: const Text('保存'),
        ),
      ],
    );
  }
}

IconData _iconFor(EntryType type) => switch (type) {
  EntryType.login => Icons.key_outlined,
  EntryType.otp => Icons.timer_outlined,
  EntryType.recoveryCodes => Icons.grid_3x3_outlined,
  EntryType.secureNote => Icons.note_outlined,
};

String _labelFor(EntryType type) => switch (type) {
  EntryType.login => '登录密码',
  EntryType.otp => 'OTP',
  EntryType.recoveryCodes => '恢复码',
  EntryType.secureNote => '安全笔记',
};
