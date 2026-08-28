import 'dart:async';

import 'package:authenticator_vault/src/features/vault/desktop_title_bar.dart';
import 'package:authenticator_vault/src/features/vault/vault_service.dart';
import 'package:authenticator_vault/src/l10n.dart';
import 'package:flutter/material.dart';

enum _SettingsSection { general, security, sync, health, about }

class SettingsPage extends StatefulWidget {
  const SettingsPage({
    required this.service,
    required this.workspaces,
    required this.selectedWorkspaceId,
    required this.handles,
    required this.onWorkspacesChanged,
    required this.onVaultChanged,
    super.key,
  });

  final ProductivityVaultService service;
  final List<WorkspaceInfo> workspaces;
  final String? selectedWorkspaceId;
  final Map<String, BigInt> handles;
  final ValueChanged<List<WorkspaceInfo>> onWorkspacesChanged;
  final VoidCallback onVaultChanged;

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  _SettingsSection section = _SettingsSection.general;
  late List<WorkspaceInfo> workspaces = List.of(widget.workspaces);
  late String? selectedWorkspaceId = widget.selectedWorkspaceId;
  final endpoint = TextEditingController();
  final username = TextEditingController();
  final password = TextEditingController();
  late final symbolCharacters = TextEditingController(
    text: widget.service.preferences.value.passwordSymbols,
  );
  bool allowInsecureHttp = false;
  bool autoSync = true;
  bool nonMeteredOnly = false;
  bool passwordStored = false;
  bool busy = false;
  List<PasswordHealthFinding>? health;
  bool canQuickUnlock = false;
  SyncSummary? lastSync;
  List<SyncConflictItem> conflicts = const [];
  List<SyncBackupItem> backups = const [];
  List<SyncDiagnosticItem> diagnostics = const [];
  bool restorePending = false;
  bool attachmentConflict = false;

  WorkspaceInfo? get selected =>
      workspaces.where((item) => item.id == selectedWorkspaceId).firstOrNull;

  @override
  void initState() {
    super.initState();
    _loadSyncFields();
    unawaited(_refreshSyncDataSilently());
    widget.service.canQuickUnlock().then((value) {
      if (mounted) setState(() => canQuickUnlock = value);
    });
  }

  @override
  void dispose() {
    endpoint.dispose();
    username.dispose();
    password.dispose();
    symbolCharacters.dispose();
    super.dispose();
  }

  void _loadSyncFields() {
    final settings = selected?.sync ?? const WorkspaceSyncSettings();
    endpoint.text = settings.endpoint;
    username.text = settings.username;
    password.clear();
    allowInsecureHttp = settings.allowInsecureHttp;
    autoSync = settings.autoSync;
    nonMeteredOnly = settings.nonMeteredOnly;
    passwordStored = settings.passwordStored;
  }

  Future<void> _run(Future<void> Function() action, {String? success}) async {
    if (busy) return;
    setState(() => busy = true);
    try {
      await action();
      if (success != null && mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text(success)));
      }
    } on Object {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(context.tr('操作失败，请检查设置、凭据和网络状态。'))),
        );
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> _saveSync() async {
    final workspace = selected;
    if (workspace == null) return;
    await _run(() async {
      workspaces = await widget.service.saveWorkspaceSync(
        workspace,
        WorkspaceSyncSettings(
          endpoint: endpoint.text,
          username: username.text,
          allowInsecureHttp: allowInsecureHttp,
          autoSync: autoSync,
          nonMeteredOnly: nonMeteredOnly,
          passwordStored: passwordStored,
        ),
        password: password.text.isEmpty ? null : password.text,
      );
      password.clear();
      widget.onWorkspacesChanged(workspaces);
      if (mounted) setState(() {});
    }, success: context.tr('同步设置已保存。'));
  }

  Future<void> _syncNow() async {
    final workspace = selected;
    final handle = widget.handles[workspace?.id];
    if (workspace == null || handle == null) return;
    if (!widget.service.isVaultWritable(handle)) return;
    await _run(() async {
      lastSync = await widget.service.syncConfiguredWorkspace(
        handle,
        workspace,
        passwordOverride: password.text.isEmpty ? null : password.text,
      );
      await _loadSyncData();
      widget.onVaultChanged();
      if (mounted) setState(() {});
    }, success: context.tr('同步完成。'));
  }

  Future<void> _loadSyncData() async {
    final workspace = selected;
    final handle = widget.handles[workspace?.id];
    if (workspace == null) return;
    final state = await widget.service.syncState(workspace.id);
    restorePending = state.restorePending;
    attachmentConflict = state.attachmentConflict;
    diagnostics = await widget.service.listSyncDiagnostics(workspace.id);
    if (handle != null) {
      conflicts = await widget.service.listSyncConflicts(handle);
      backups = await widget.service.listSyncBackups(handle, workspace.id);
    } else {
      conflicts = const [];
      backups = const [];
    }
  }

  Future<void> _refreshSyncDataSilently() async {
    try {
      await _loadSyncData();
      if (mounted) setState(() {});
    } on Object {
      // The regular action path surfaces typed failures; initial rendering
      // remains usable if optional sync state is unavailable.
    }
  }

  Future<void> _resolveConflict(SyncConflictItem conflict) async {
    final handle = widget.handles[selectedWorkspaceId];
    if (handle == null) return;
    final success = context.tr('冲突已解决；请再次同步以发送结果。');
    final choices = <String, SyncConflictChoice>{
      for (final field in conflict.fields) field: SyncConflictChoice.primary,
    };
    final accepted = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (context, setDialogState) => AlertDialog(
          title: Text(context.tr('解决冲突：{title}', {'title': conflict.title})),
          content: SizedBox(
            width: 520,
            child: ListView(
              shrinkWrap: true,
              children: [
                Text(context.tr('逐字段选择保留当前设备或另一设备的值。密码内容不会在这里显示。')),
                const SizedBox(height: 12),
                for (final field in conflict.fields)
                  DropdownButtonFormField<SyncConflictChoice>(
                    initialValue: choices[field],
                    decoration: InputDecoration(labelText: field),
                    items: [
                      DropdownMenuItem(
                        value: SyncConflictChoice.primary,
                        child: Text(context.tr('当前版本')),
                      ),
                      DropdownMenuItem(
                        value: SyncConflictChoice.alternate,
                        child: Text(context.tr('另一设备版本')),
                      ),
                    ],
                    onChanged: (value) =>
                        setDialogState(() => choices[field] = value!),
                  ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(dialogContext, false),
              child: Text(context.tr('取消')),
            ),
            FilledButton(
              onPressed: () => Navigator.pop(dialogContext, true),
              child: Text(context.tr('应用解决方案')),
            ),
          ],
        ),
      ),
    );
    if (accepted != true) return;
    await _run(() async {
      await widget.service.resolveSyncConflict(
        handle,
        conflict.id,
        SyncConflictChoice.primary,
        fieldChoices: choices,
      );
      await _loadSyncData();
      widget.onVaultChanged();
      if (mounted) setState(() {});
    }, success: success);
  }

  Future<void> _restoreBackup(SyncBackupItem backup) async {
    final workspace = selected;
    final handle = widget.handles[workspace?.id];
    if (workspace == null || handle == null) return;
    final success = context.tr('备份已恢复，自动同步已暂停。');
    final accepted = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(context.tr('恢复加密备份？')),
        content: Text(context.tr('当前文件会先自动备份。恢复后自动同步将暂停，避免直接覆盖远端。')),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text(context.tr('取消')),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(context.tr('恢复并暂停同步')),
          ),
        ],
      ),
    );
    if (accepted != true) return;
    await _run(() async {
      await widget.service.restoreSyncBackup(handle, workspace.id, backup.id);
      workspaces = await widget.service.saveWorkspaceSync(
        workspace,
        WorkspaceSyncSettings(
          endpoint: workspace.sync.endpoint,
          username: workspace.sync.username,
          allowInsecureHttp: workspace.sync.allowInsecureHttp,
          autoSync: false,
          nonMeteredOnly: workspace.sync.nonMeteredOnly,
          passwordStored: workspace.sync.passwordStored,
        ),
      );
      widget.onWorkspacesChanged(workspaces);
      await _loadSyncData();
      widget.onVaultChanged();
      if (mounted) setState(() {});
    }, success: success);
  }

  Future<void> _completeRestore(RestoreSyncDecision decision) async {
    final workspace = selected;
    final handle = widget.handles[workspace?.id];
    if (workspace == null || handle == null) return;
    final success = context.tr(
      decision == RestoreSyncDecision.merge
          ? '恢复内容已与远端安全合并。'
          : '远端已通过条件写入替换并完成校验。',
    );
    await _run(() async {
      lastSync = await widget.service.completeRestoreSync(
        handle,
        workspace,
        decision,
        passwordOverride: password.text.isEmpty ? null : password.text,
      );
      await _loadSyncData();
      widget.onVaultChanged();
      if (mounted) setState(() {});
    }, success: success);
  }

  Future<void> _exportDiagnostics() async {
    final workspace = selected;
    if (workspace == null) return;
    final success = context.tr('脱敏诊断已导出。');
    final path = await widget.service.chooseDiagnosticsExportPath();
    if (path == null) return;
    await _run(
      () => widget.service.exportSyncDiagnostics(workspace.id, path),
      success: success,
    );
  }

  Future<void> _scanHealth() async {
    final handle = widget.handles[selectedWorkspaceId];
    if (handle == null) return;
    await _run(() async {
      health = await widget.service.passwordHealth(handle);
      if (mounted) setState(() {});
    });
  }

  Future<void> _toggleQuickUnlock(bool enabled) async {
    final workspace = selected;
    if (workspace == null) return;
    await _run(() async {
      if (enabled) {
        final handle = widget.handles[workspace.id];
        if (handle == null) throw StateError('workspace is locked');
        workspaces = await widget.service.enableQuickUnlock(
          UnlockedWorkspace(workspace: workspace, handleId: handle),
        );
      } else {
        workspaces = await widget.service.disableQuickUnlock(workspace);
      }
      widget.onWorkspacesChanged(workspaces);
      if (mounted) setState(() {});
    }, success: context.tr(enabled ? '快速解锁已启用。' : '快速解锁已关闭。'));
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    body: Column(
      children: [
        DesktopTitleBar(
          leading: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              IconButton(
                tooltip: context.tr('返回'),
                onPressed: () => Navigator.pop(context),
                icon: const Icon(Icons.arrow_back),
              ),
              Text(
                context.tr('设置'),
                style: const TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          search: const SizedBox(),
          actions: const [],
        ),
        Expanded(
          child: Row(
            children: [
              SizedBox(
                width: 220,
                child: ColoredBox(
                  color: Theme.of(context).colorScheme.surfaceContainerLow,
                  child: ListView(
                    padding: const EdgeInsets.all(10),
                    children: [
                      for (final value in _SettingsSection.values)
                        ListTile(
                          selected: section == value,
                          leading: Icon(_sectionIcon(value), size: 20),
                          title: Text(context.tr(_sectionLabel(value))),
                          onTap: () => setState(() => section = value),
                        ),
                    ],
                  ),
                ),
              ),
              const VerticalDivider(width: 1),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    if (busy) const LinearProgressIndicator(),
                    Expanded(
                      child: SingleChildScrollView(
                        padding: const EdgeInsets.fromLTRB(28, 24, 28, 28),
                        child: Align(
                          alignment: Alignment.topLeft,
                          child: ConstrainedBox(
                            constraints: const BoxConstraints(maxWidth: 760),
                            child: _sectionBody(),
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ],
    ),
  );

  Widget _sectionBody() => switch (section) {
    _SettingsSection.general => _general(),
    _SettingsSection.security => _security(),
    _SettingsSection.sync => _sync(),
    _SettingsSection.health => _health(),
    _SettingsSection.about => _about(),
  };

  Widget _heading(String title, String subtitle) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Text(title, style: Theme.of(context).textTheme.headlineSmall),
      const SizedBox(height: 6),
      Text(subtitle, style: Theme.of(context).textTheme.bodyMedium),
      const SizedBox(height: 24),
    ],
  );

  Widget _general() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      _heading(context.tr('通用'), context.tr('管理当前应用的界面与常用行为。')),
      DropdownButtonFormField<AppThemePreference>(
        initialValue: widget.service.preferences.value.theme,
        decoration: InputDecoration(labelText: context.tr('外观')),
        items: [
          DropdownMenuItem(
            value: AppThemePreference.system,
            child: Text(context.tr('跟随系统')),
          ),
          DropdownMenuItem(
            value: AppThemePreference.light,
            child: Text(context.tr('浅色')),
          ),
          DropdownMenuItem(
            value: AppThemePreference.dark,
            child: Text(context.tr('深色')),
          ),
        ],
        onChanged: busy
            ? null
            : (value) => _run(() => widget.service.setThemePreference(value!)),
      ),
      const SizedBox(height: 16),
      DropdownButtonFormField<AppLanguage>(
        initialValue: widget.service.preferences.value.language,
        decoration: InputDecoration(labelText: context.tr('语言')),
        items: [
          DropdownMenuItem(
            value: AppLanguage.zhHans,
            child: Text(context.tr('简体中文')),
          ),
          DropdownMenuItem(
            value: AppLanguage.english,
            child: Text(context.tr('English')),
          ),
        ],
        onChanged: busy
            ? null
            : (value) => _run(() => widget.service.setLanguage(value!)),
      ),
      const SizedBox(height: 16),
      TextField(
        controller: symbolCharacters,
        decoration: InputDecoration(
          labelText: context.tr('特殊字符'),
          helperText: context.tr('仅允许 ASCII 标点；使用结果时保存为全局默认'),
        ),
      ),
      const SizedBox(height: 10),
      Wrap(
        spacing: 10,
        children: [
          FilledButton(
            onPressed: busy
                ? null
                : () => _run(() async {
                    symbolCharacters.text = await widget.service
                        .setPasswordSymbols(symbolCharacters.text);
                  }),
            child: Text(context.tr('保存')),
          ),
          TextButton(
            onPressed: busy
                ? null
                : () => _run(() async {
                    const defaults = AppPreferences();
                    symbolCharacters.text = await widget.service
                        .setPasswordSymbols(defaults.passwordSymbols);
                  }),
            child: Text(context.tr('恢复默认')),
          ),
        ],
      ),
    ],
  );

  Widget _security() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      _heading(context.tr('安全'), context.tr('安全选项会应用到所有 Workspace。')),
      DropdownButtonFormField<int>(
        initialValue: widget.service.autoLockSeconds,
        decoration: InputDecoration(labelText: context.tr('进入后台后自动锁定')),
        items: [
          DropdownMenuItem(value: 0, child: Text(context.tr('立即'))),
          DropdownMenuItem(value: 30, child: Text(context.tr('30 秒'))),
          DropdownMenuItem(value: 60, child: Text(context.tr('1 分钟'))),
          DropdownMenuItem(value: 300, child: Text(context.tr('5 分钟（默认）'))),
          DropdownMenuItem(value: 900, child: Text(context.tr('15 分钟'))),
        ],
        onChanged: busy
            ? null
            : (value) => _run(
                () => widget.service.setAutoLockSeconds(value!),
                success: context.tr('自动锁定设置已更新。'),
              ),
      ),
      const SizedBox(height: 16),
      _workspacePicker(),
      const SizedBox(height: 12),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        secondary: const Icon(Icons.fingerprint),
        title: Text(context.tr('强生物识别快速解锁')),
        subtitle: Text(
          widget.handles[selectedWorkspaceId] == null
              ? context.tr('当前版本仅 Android 支持；请先用主密码解锁此 Workspace。')
              : context.tr('密钥由 Android Keystore 保护，不使用设备 PIN 回退。'),
        ),
        value: selected?.quickUnlockEnabled ?? false,
        onChanged:
            busy ||
                (widget.handles[selectedWorkspaceId] == null &&
                    selected?.quickUnlockEnabled != true) ||
                (!canQuickUnlock && selected?.quickUnlockEnabled != true)
            ? null
            : _toggleQuickUnlock,
      ),
    ],
  );

  Widget _workspacePicker() => DropdownButtonFormField<String>(
    initialValue: selectedWorkspaceId,
    decoration: const InputDecoration(labelText: 'Workspace'),
    items: workspaces
        .map((item) => DropdownMenuItem(value: item.id, child: Text(item.name)))
        .toList(),
    onChanged: (value) => setState(() {
      selectedWorkspaceId = value;
      _loadSyncFields();
      health = null;
      lastSync = null;
      conflicts = const [];
      backups = const [];
      diagnostics = const [];
      restorePending = false;
      attachmentConflict = false;
      unawaited(_refreshSyncDataSilently());
    }),
  );

  Widget _sync() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      _heading(
        context.tr('同步'),
        context.tr('每个 Workspace 使用独立 WebDAV 配置。密码可选存入系统安全存储。'),
      ),
      _workspacePicker(),
      const SizedBox(height: 16),
      TextField(
        controller: endpoint,
        decoration: InputDecoration(
          labelText: context.tr('WebDAV 文件 URL'),
          hintText: 'https://dav.example.com/personal.kdbx',
        ),
      ),
      const SizedBox(height: 12),
      TextField(
        controller: username,
        decoration: InputDecoration(labelText: context.tr('用户名')),
      ),
      const SizedBox(height: 12),
      TextField(
        controller: password,
        obscureText: true,
        decoration: InputDecoration(
          labelText: context.tr(passwordStored ? '密码（留空则保留已保存密码）' : '密码'),
        ),
      ),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: Text(context.tr('将密码保存到系统安全存储')),
        value: passwordStored,
        onChanged: (value) => setState(() => passwordStored = value),
      ),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: Text(context.tr('自动双向同步')),
        subtitle: Text(context.tr('仅在应用前台且 Workspace 已解锁时运行')),
        value: autoSync,
        onChanged: (value) => setState(() => autoSync = value),
      ),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: Text(context.tr('仅非计费网络')),
        value: nonMeteredOnly,
        onChanged: (value) => setState(() => nonMeteredOnly = value),
      ),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: Text(context.tr('允许不安全 HTTP')),
        subtitle: Text(context.tr('默认关闭，仅用于受信任的局域网测试环境')),
        value: allowInsecureHttp,
        onChanged: (value) => setState(() => allowInsecureHttp = value),
      ),
      const SizedBox(height: 12),
      Wrap(
        spacing: 12,
        children: [
          FilledButton.icon(
            onPressed: busy ? null : _saveSync,
            icon: const Icon(Icons.save_outlined),
            label: Text(context.tr('保存')),
          ),
          OutlinedButton.icon(
            onPressed:
                busy ||
                    widget.handles[selectedWorkspaceId] == null ||
                    !widget.service.isVaultWritable(
                      widget.handles[selectedWorkspaceId]!,
                    )
                ? null
                : _syncNow,
            icon: const Icon(Icons.sync),
            label: Text(context.tr('立即同步')),
          ),
          OutlinedButton.icon(
            onPressed: busy || selected == null
                ? null
                : () => _run(() async {
                    await _loadSyncData();
                    if (mounted) setState(() {});
                  }),
            icon: const Icon(Icons.refresh),
            label: Text(context.tr('刷新同步状态')),
          ),
        ],
      ),
      if (lastSync case final result?) ...[
        const SizedBox(height: 16),
        Card(
          child: ListTile(
            leading: const Icon(Icons.cloud_done_outlined),
            title: Text(
              context.tr('同步结果：{action}', {'action': result.action.name}),
            ),
            subtitle: Text(
              context.tr('自动合并 {merged} 项，新增冲突 {created} 个，待处理 {pending} 个。', {
                'merged': result.autoMergedObjects.toString(),
                'created': result.createdConflicts.toString(),
                'pending': result.pendingConflicts.toString(),
              }),
            ),
          ),
        ),
      ],
      const SizedBox(height: 24),
      Text(context.tr('冲突中心'), style: Theme.of(context).textTheme.titleMedium),
      const SizedBox(height: 6),
      if (conflicts.isEmpty)
        Text(context.tr('没有待处理冲突。'))
      else
        for (final conflict in conflicts)
          ListTile(
            contentPadding: EdgeInsets.zero,
            leading: const Icon(Icons.call_split_outlined),
            title: Text(conflict.title),
            subtitle: Text(conflict.fields.join(' · ')),
            trailing: TextButton(
              onPressed: busy ? null : () => _resolveConflict(conflict),
              child: Text(context.tr('解决')),
            ),
          ),
      const SizedBox(height: 20),
      Text(context.tr('加密备份'), style: Theme.of(context).textTheme.titleMedium),
      Text(context.tr('备份保持 KDBX 加密状态，并按 Workspace 独立保存。')),
      if (restorePending)
        Card(
          color: Theme.of(context).colorScheme.tertiaryContainer,
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  context.tr('恢复后的同步正在等待你的决定'),
                  style: Theme.of(context).textTheme.titleSmall,
                ),
                Text(context.tr('“安全合并”保留双方修改；“替换远端”会先备份远端，并使用 ETag 条件写入。')),
                const SizedBox(height: 10),
                Wrap(
                  spacing: 10,
                  children: [
                    FilledButton(
                      onPressed: busy
                          ? null
                          : () => _completeRestore(RestoreSyncDecision.merge),
                      child: Text(context.tr('安全合并')),
                    ),
                    OutlinedButton(
                      onPressed: busy
                          ? null
                          : () => _completeRestore(
                              RestoreSyncDecision.replaceRemote,
                            ),
                      child: Text(context.tr('替换远端')),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      if (attachmentConflict)
        ListTile(
          contentPadding: EdgeInsets.zero,
          leading: const Icon(Icons.attachment_outlined),
          title: Text(context.tr('附件在多端同时发生变化，同步已安全停止。')),
          subtitle: Text(context.tr('当前版本不会猜测合并附件；请在其中一端撤销附件变化后重试。')),
        ),
      for (final backup in backups.take(8))
        ListTile(
          contentPadding: EdgeInsets.zero,
          leading: const Icon(Icons.restore_outlined),
          title: Text(backup.createdAt.toLocal().toString()),
          subtitle: Text('${backup.origin} · ${backup.encryptedSize} B'),
          trailing: TextButton(
            onPressed: busy ? null : () => _restoreBackup(backup),
            child: Text(context.tr('恢复')),
          ),
        ),
      const SizedBox(height: 20),
      Text(context.tr('同步诊断'), style: Theme.of(context).textTheme.titleMedium),
      Text(context.tr('仅记录阶段、错误码、耗时和计数；不包含密码、OTP、URL 或条目内容。')),
      const SizedBox(height: 8),
      Wrap(
        spacing: 10,
        children: [
          OutlinedButton.icon(
            onPressed: busy || selected == null ? null : _exportDiagnostics,
            icon: const Icon(Icons.file_download_outlined),
            label: Text(context.tr('导出脱敏诊断')),
          ),
          TextButton(
            onPressed: busy || selected == null
                ? null
                : () => _run(() async {
                    await widget.service.clearSyncDiagnostics(selected!.id);
                    diagnostics = const [];
                    if (mounted) setState(() {});
                  }),
            child: Text(context.tr('清除诊断')),
          ),
        ],
      ),
      if (diagnostics.isNotEmpty)
        Text(
          context.tr('最近记录：{count} 条', {
            'count': diagnostics.length.toString(),
          }),
        ),
    ],
  );

  Widget _health() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      _heading(
        context.tr('密码健康'),
        context.tr('检查完全在本机 Rust 核心内完成，不上传密码或密码摘要。'),
      ),
      _workspacePicker(),
      const SizedBox(height: 16),
      DropdownButtonFormField<int>(
        initialValue: widget.service.stalePasswordDays,
        decoration: InputDecoration(labelText: context.tr('长期未修改阈值')),
        items: [
          DropdownMenuItem(value: 0, child: Text(context.tr('禁用'))),
          DropdownMenuItem(value: 90, child: Text(context.tr('90 天'))),
          DropdownMenuItem(value: 180, child: Text(context.tr('180 天（默认）'))),
          DropdownMenuItem(value: 365, child: Text(context.tr('365 天'))),
        ],
        onChanged: (value) => _run(
          () => widget.service.setStalePasswordDays(value!),
          success: context.tr('健康检查阈值已更新。'),
        ),
      ),
      const SizedBox(height: 16),
      FilledButton.icon(
        onPressed: busy || widget.handles[selectedWorkspaceId] == null
            ? null
            : _scanHealth,
        icon: const Icon(Icons.health_and_safety_outlined),
        label: Text(context.tr('开始本地检查')),
      ),
      if (health case final findings?) ...[
        const SizedBox(height: 20),
        Text(
          findings.isEmpty
              ? context.tr('未发现风险')
              : context.tr('发现 {count} 个需关注的条目', {
                  'count': findings.length.toString(),
                }),
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        for (final finding in findings)
          ListTile(
            contentPadding: EdgeInsets.zero,
            leading: const Icon(Icons.warning_amber_outlined),
            title: Text(
              selected?.id == selectedWorkspaceId
                  ? context.tr('条目 {id}', {
                      'id': finding.entryId.substring(0, 8),
                    })
                  : context.tr('风险条目'),
            ),
            subtitle: Text(
              finding.risks
                  .map((risk) => context.tr(_riskLabel(risk)))
                  .join(context.tr('、')),
            ),
          ),
      ],
    ],
  );

  Widget _about() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      _heading(context.tr('关于'), 'Authenticator Vault 0.4.0'),
      ListTile(
        contentPadding: EdgeInsets.zero,
        leading: const Icon(Icons.shield_outlined),
        title: Text(context.tr('离线优先 KDBX 密码与 OTP 工具')),
        subtitle: const Text(
          'KDBX 4.1 · Android / iOS / Linux / macOS / Windows',
        ),
      ),
    ],
  );
}

String _sectionLabel(_SettingsSection value) => switch (value) {
  _SettingsSection.general => '通用',
  _SettingsSection.security => '安全',
  _SettingsSection.sync => '同步',
  _SettingsSection.health => '密码健康',
  _SettingsSection.about => '关于',
};

IconData _sectionIcon(_SettingsSection value) => switch (value) {
  _SettingsSection.general => Icons.tune,
  _SettingsSection.security => Icons.security_outlined,
  _SettingsSection.sync => Icons.sync,
  _SettingsSection.health => Icons.health_and_safety_outlined,
  _SettingsSection.about => Icons.info_outline,
};

String _riskLabel(PasswordHealthRisk value) => switch (value) {
  PasswordHealthRisk.empty => '空密码',
  PasswordHealthRisk.duplicate => '重复密码',
  PasswordHealthRisk.weak => '弱密码',
  PasswordHealthRisk.stale => '长期未修改',
  PasswordHealthRisk.missingOtp => '未配置 OTP',
};
