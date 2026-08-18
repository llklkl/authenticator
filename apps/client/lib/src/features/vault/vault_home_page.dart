import 'dart:async';

import 'package:authenticator_vault/src/features/security/platform_security_service.dart';
import 'package:authenticator_vault/src/features/vault/vault_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

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
  final _codes = <String, OtpValue>{};
  final _searchController = TextEditingController();
  List<WorkspaceInfo> _workspaces = [];
  String? _selectedId;
  String _query = '';
  bool _loading = true;
  bool _privacyOverlay = false;
  Object? _loadError;
  Timer? _ticker;
  Stopwatch? _backgroundElapsed;
  StreamSubscription<void>? _screenOffSubscription;
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
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden ||
        state == AppLifecycleState.detached) {
      _backgroundElapsed ??= Stopwatch()..start();
      if (mounted) setState(() => _privacyOverlay = true);
      unawaited(_securityCoordinator.setBackgrounded(true));
    } else if (state == AppLifecycleState.resumed) {
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
    if (mounted) setState(() => _privacyOverlay = false);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _ticker?.cancel();
    unawaited(_screenOffSubscription?.cancel());
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
      final entries = await widget.vaultService.listEntries(unlocked.handleId);
      setState(() {
        _workspaces = [..._workspaces, unlocked.workspace];
        _selectedId = unlocked.workspace.id;
        _handles[unlocked.workspace.id] = unlocked.handleId;
        _entries[unlocked.workspace.id] = entries;
      });
      await _securityCoordinator.setUnlockedCount(_handles.length);
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
      final entries = await widget.vaultService.listEntries(handle);
      setState(() {
        _handles[workspace.id] = handle;
        _entries[workspace.id] = entries;
      });
      await _securityCoordinator.setUnlockedCount(_handles.length);
      await _refreshOtp();
    });
  }

  Future<void> _lockAll() async {
    await widget.vaultService.lockAll();
    if (!mounted) return;
    setState(() {
      _handles.clear();
      _entries.clear();
      _codes.clear();
    });
    await _securityCoordinator.setUnlockedCount(0);
  }

  Future<void> _refreshEntries() async {
    final handle = _selectedHandle;
    final workspace = _selected;
    if (handle == null || workspace == null) return;
    final entries = await widget.vaultService.listEntries(handle);
    if (!mounted || handle != _handles[workspace.id]) return;
    setState(() => _entries[workspace.id] = entries);
    await _refreshOtp();
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
      await widget.vaultService.createEntry(handle, draft);
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

  Future<void> _syncWebDav() async {
    final handle = _selectedHandle;
    final workspace = _selected;
    if (handle == null || workspace == null) return;
    final settings = await _sensitiveDialog<WebDavSettings>(
      builder: (_) => const _WebDavDialog(),
    );
    if (settings == null || !mounted) return;
    await _guarded(() async {
      final result = await widget.vaultService.syncWebDav(
        handle,
        workspace.id,
        settings,
      );
      await _refreshEntries();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            result.merged
                ? '同步完成：已合并远端变更（${result.attempts} 次尝试）。'
                : '同步完成（${result.attempts} 次尝试）。',
          ),
        ),
      );
    });
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
    final confirmed = await _sensitiveDialog<bool>(
      builder: (context) => AlertDialog(
        title: const Text('删除条目？'),
        content: Text('“${item.title}”会从 Vault 删除，并写入 KDBX 删除记录。'),
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
      appBar: AppBar(
        title: const Text('Authenticator Vault'),
        actions: [
          IconButton(
            onPressed: _securityService == null || _selected == null
                ? null
                : _showSecuritySettings,
            tooltip: '安全设置',
            icon: const Icon(Icons.security_outlined),
          ),
          IconButton(
            onPressed: _handles.isEmpty ? null : _lockAll,
            tooltip: '锁定全部 Workspace',
            icon: const Icon(Icons.lock_outline),
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: Stack(
        children: [
          LayoutBuilder(
            builder: (context, constraints) {
              if (_workspaces.isEmpty) return _buildWelcome();
              if (constraints.maxWidth >= 800) {
                return Row(
                  children: [
                    _buildRail(),
                    const VerticalDivider(width: 1),
                    Expanded(child: _buildWorkspace()),
                  ],
                );
              }
              return _buildWorkspace(showPicker: true);
            },
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

  Widget _buildRail() {
    final index = _workspaces.indexWhere(
      (workspace) => workspace.id == _selectedId,
    );
    return NavigationRail(
      selectedIndex: index < 0 ? 0 : index,
      labelType: NavigationRailLabelType.all,
      leading: Padding(
        padding: const EdgeInsets.symmetric(vertical: 16),
        child: PopupMenuButton<String>(
          tooltip: '添加 Workspace',
          icon: const Icon(Icons.add_circle_outline),
          onSelected: (value) =>
              value == 'create' ? _createWorkspace() : _importWorkspace(),
          itemBuilder: (_) => const [
            PopupMenuItem(value: 'create', child: Text('新建 Workspace')),
            PopupMenuItem(value: 'import', child: Text('导入 KDBX')),
          ],
        ),
      ),
      onDestinationSelected: (value) =>
          setState(() => _selectedId = _workspaces[value].id),
      destinations: [
        for (final workspace in _workspaces)
          NavigationRailDestination(
            icon: Icon(
              _handles.containsKey(workspace.id)
                  ? Icons.lock_open
                  : Icons.lock_outline,
            ),
            label: Text(workspace.name),
          ),
      ],
    );
  }

  Widget _buildWorkspace({bool showPicker = false}) {
    final workspace = _selected;
    if (workspace == null) return const SizedBox();
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.fromLTRB(24, 16, 24, 24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (showPicker) ...[
              DropdownButtonFormField<String>(
                initialValue: workspace.id,
                decoration: const InputDecoration(labelText: 'Workspace'),
                items: [
                  for (final item in _workspaces)
                    DropdownMenuItem(value: item.id, child: Text(item.name)),
                ],
                onChanged: (value) => setState(() => _selectedId = value),
              ),
              const SizedBox(height: 16),
            ] else
              Text(
                workspace.name,
                style: Theme.of(context).textTheme.headlineSmall,
              ),
            const SizedBox(height: 16),
            if (_selectedHandle == null)
              Expanded(
                child: _LockedWorkspace(
                  workspace: workspace,
                  onUnlock: _unlock,
                  onQuickUnlock: workspace.quickUnlockEnabled
                      ? _quickUnlock
                      : null,
                ),
              )
            else ...[
              LayoutBuilder(
                builder: (context, constraints) {
                  if (constraints.maxWidth < 620) {
                    return Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        _buildSearchField(),
                        const SizedBox(height: 10),
                        Align(
                          alignment: Alignment.centerRight,
                          child: _buildEntryActions(),
                        ),
                      ],
                    );
                  }
                  return Row(
                    children: [
                      Expanded(child: _buildSearchField()),
                      const SizedBox(width: 12),
                      _buildEntryActions(),
                    ],
                  );
                },
              ),
              const SizedBox(height: 20),
              Expanded(child: _buildEntryList()),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildSearchField() => TextField(
    controller: _searchController,
    onChanged: (value) => setState(() => _query = value),
    decoration: const InputDecoration(
      hintText: '搜索标题、账号或标签',
      prefixIcon: Icon(Icons.search),
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
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.primary,
            borderRadius: BorderRadius.circular(20),
          ),
          child: Text(
            '＋ 新增',
            style: TextStyle(color: Theme.of(context).colorScheme.onPrimary),
          ),
        ),
      ),
      const SizedBox(width: 8),
      OutlinedButton.icon(
        onPressed: _importOtp,
        icon: const Icon(Icons.qr_code_2),
        label: const Text('导入 OTP'),
      ),
      IconButton(
        onPressed: _syncWebDav,
        tooltip: 'WebDAV 同步',
        icon: const Icon(Icons.sync),
      ),
    ],
  );

  Widget _buildEntryList() {
    final query = _query.trim().toLowerCase();
    final visible = _selectedEntries.where((entry) {
      return query.isEmpty ||
          entry.title.toLowerCase().contains(query) ||
          entry.username.toLowerCase().contains(query) ||
          entry.tags.any((tag) => tag.toLowerCase().contains(query));
    }).toList();
    if (visible.isEmpty) {
      return Center(
        child: Text(query.isEmpty ? '这个 Workspace 还是空的' : '没有匹配的条目'),
      );
    }
    return ListView.separated(
      itemCount: visible.length,
      separatorBuilder: (_, _) => const SizedBox(height: 10),
      itemBuilder: (_, index) {
        final item = visible[index];
        final otp = _codes[item.id];
        return Card(
          child: ListTile(
            leading: CircleAvatar(child: Icon(_iconFor(item.type))),
            title: Text(item.title),
            subtitle: Text(
              item.username.isEmpty ? _labelFor(item.type) : item.username,
            ),
            trailing: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (otp != null) ...[
                  Text(
                    otp.code,
                    style: Theme.of(context).textTheme.titleLarge
                        ?.copyWith(letterSpacing: 3),
                  ),
                  IconButton(
                    onPressed: () => _copy(otp.code),
                    icon: const Icon(Icons.copy_outlined),
                  ),
                ],
                PopupMenuButton<String>(
                  onSelected: (action) {
                    switch (action) {
                      case 'password':
                        _reveal(item, false);
                      case 'notes':
                        _reveal(item, true);
                      case 'edit':
                        _editEntry(item);
                      case 'delete':
                        _deleteEntry(item);
                    }
                  },
                  itemBuilder: (_) => [
                    if (item.hasPassword)
                      const PopupMenuItem(
                        value: 'password',
                        child: Text('显示密码'),
                      ),
                    const PopupMenuItem(value: 'notes', child: Text('显示受保护内容')),
                    const PopupMenuItem(value: 'edit', child: Text('编辑')),
                    const PopupMenuItem(value: 'delete', child: Text('删除')),
                  ],
                ),
              ],
            ),
          ),
        );
      },
    );
  }
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
  final name = TextEditingController();
  late final path = TextEditingController(text: widget.initialPath);
  final password = TextEditingController();

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
          _ImportWorkspaceRequest(
            name.text.trim(),
            path.text.trim(),
            password.text,
          ),
        ),
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

class _WebDavDialog extends StatefulWidget {
  const _WebDavDialog();

  @override
  State<_WebDavDialog> createState() => _WebDavDialogState();
}

class _WebDavDialogState extends State<_WebDavDialog> {
  final endpoint = TextEditingController();
  final username = TextEditingController();
  final password = TextEditingController();
  bool allowInsecureHttp = false;

  @override
  void dispose() {
    endpoint.dispose();
    username.dispose();
    password.clear();
    password.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: const Text('WebDAV 同步'),
    content: SizedBox(
      width: 520,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          TextField(
            controller: endpoint,
            autofocus: true,
            decoration: const InputDecoration(
              labelText: 'KDBX 远端完整 URL',
              hintText: 'https://dav.example.com/vault.kdbx',
            ),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: username,
            decoration: const InputDecoration(labelText: '用户名'),
          ),
          const SizedBox(height: 12),
          TextField(
            controller: password,
            obscureText: true,
            autocorrect: false,
            enableSuggestions: false,
            decoration: const InputDecoration(labelText: 'WebDAV 密码'),
          ),
          CheckboxListTile(
            contentPadding: EdgeInsets.zero,
            value: allowInsecureHttp,
            onChanged: (value) =>
                setState(() => allowInsecureHttp = value ?? false),
            title: const Text('允许不安全的 HTTP（仅限可信局域网）'),
          ),
          const Text('凭据仅用于本次同步，不会写入 Workspace 元数据。'),
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
          if (endpoint.text.trim().isEmpty) return;
          Navigator.pop(
            context,
            WebDavSettings(
              endpoint: endpoint.text.trim(),
              username: username.text,
              password: password.text,
              allowInsecureHttp: allowInsecureHttp,
            ),
          );
        },
        child: const Text('同步'),
      ),
    ],
  );
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
