import 'package:authenticator_vault/src/features/vault/desktop_title_bar.dart';
import 'package:authenticator_vault/src/features/vault/vault_service.dart';
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
  bool allowInsecureHttp = false;
  bool autoSync = true;
  bool nonMeteredOnly = false;
  bool passwordStored = false;
  bool busy = false;
  List<PasswordHealthFinding>? health;
  bool canQuickUnlock = false;

  WorkspaceInfo? get selected =>
      workspaces.where((item) => item.id == selectedWorkspaceId).firstOrNull;

  @override
  void initState() {
    super.initState();
    _loadSyncFields();
    widget.service.canQuickUnlock().then((value) {
      if (mounted) setState(() => canQuickUnlock = value);
    });
  }

  @override
  void dispose() {
    endpoint.dispose();
    username.dispose();
    password.dispose();
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
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: Text('操作失败，请检查设置、凭据和网络状态。')));
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
    }, success: '同步设置已保存。');
  }

  Future<void> _syncNow() async {
    final workspace = selected;
    final handle = widget.handles[workspace?.id];
    if (workspace == null || handle == null) return;
    await _run(() async {
      await widget.service.syncConfiguredWorkspace(
        handle,
        workspace,
        passwordOverride: password.text.isEmpty ? null : password.text,
      );
      widget.onVaultChanged();
    }, success: '同步完成。');
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
    }, success: enabled ? '快速解锁已启用。' : '快速解锁已关闭。');
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
                tooltip: '返回',
                onPressed: () => Navigator.pop(context),
                icon: const Icon(Icons.arrow_back),
              ),
              const Text(
                '设置',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
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
                          title: Text(_sectionLabel(value)),
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
      _heading('通用', '管理当前应用的界面与常用行为。'),
      const ListTile(
        contentPadding: EdgeInsets.zero,
        leading: Icon(Icons.dark_mode_outlined),
        title: Text('外观'),
        subtitle: Text('跟随系统浅色或深色主题'),
      ),
      const ListTile(
        contentPadding: EdgeInsets.zero,
        leading: Icon(Icons.language_outlined),
        title: Text('语言'),
        subtitle: Text('简体中文'),
      ),
    ],
  );

  Widget _security() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      _heading('安全', '安全选项会应用到所有 Workspace。'),
      DropdownButtonFormField<int>(
        initialValue: widget.service.autoLockSeconds,
        decoration: const InputDecoration(labelText: '进入后台后自动锁定'),
        items: const [
          DropdownMenuItem(value: 0, child: Text('立即')),
          DropdownMenuItem(value: 30, child: Text('30 秒')),
          DropdownMenuItem(value: 60, child: Text('1 分钟')),
          DropdownMenuItem(value: 300, child: Text('5 分钟（默认）')),
          DropdownMenuItem(value: 900, child: Text('15 分钟')),
        ],
        onChanged: busy
            ? null
            : (value) => _run(
                () => widget.service.setAutoLockSeconds(value!),
                success: '自动锁定设置已更新。',
              ),
      ),
      const SizedBox(height: 16),
      _workspacePicker(),
      const SizedBox(height: 12),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        secondary: const Icon(Icons.fingerprint),
        title: const Text('强生物识别快速解锁'),
        subtitle: Text(
          widget.handles[selectedWorkspaceId] == null
              ? '当前版本仅 Android 支持；请先用主密码解锁此 Workspace。'
              : '密钥由 Android Keystore 保护，不使用设备 PIN 回退。',
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
    }),
  );

  Widget _sync() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      _heading('同步', '每个 Workspace 使用独立 WebDAV 配置。密码可选存入系统安全存储。'),
      _workspacePicker(),
      const SizedBox(height: 16),
      TextField(
        controller: endpoint,
        decoration: const InputDecoration(
          labelText: 'WebDAV 文件 URL',
          hintText: 'https://dav.example.com/personal.kdbx',
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
        decoration: InputDecoration(
          labelText: passwordStored ? '密码（留空则保留已保存密码）' : '密码',
        ),
      ),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: const Text('将密码保存到系统安全存储'),
        value: passwordStored,
        onChanged: (value) => setState(() => passwordStored = value),
      ),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: const Text('自动双向同步'),
        subtitle: const Text('仅在应用前台且 Workspace 已解锁时运行'),
        value: autoSync,
        onChanged: (value) => setState(() => autoSync = value),
      ),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: const Text('仅非计费网络'),
        value: nonMeteredOnly,
        onChanged: (value) => setState(() => nonMeteredOnly = value),
      ),
      SwitchListTile(
        contentPadding: EdgeInsets.zero,
        title: const Text('允许不安全 HTTP'),
        subtitle: const Text('默认关闭，仅用于受信任的局域网测试环境'),
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
            label: const Text('保存'),
          ),
          OutlinedButton.icon(
            onPressed: busy || widget.handles[selectedWorkspaceId] == null
                ? null
                : _syncNow,
            icon: const Icon(Icons.sync),
            label: const Text('立即同步'),
          ),
        ],
      ),
    ],
  );

  Widget _health() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      _heading('密码健康', '检查完全在本机 Rust 核心内完成，不上传密码或密码摘要。'),
      _workspacePicker(),
      const SizedBox(height: 16),
      DropdownButtonFormField<int>(
        initialValue: widget.service.stalePasswordDays,
        decoration: const InputDecoration(labelText: '长期未修改阈值'),
        items: const [
          DropdownMenuItem(value: 0, child: Text('关闭')),
          DropdownMenuItem(value: 90, child: Text('90 天')),
          DropdownMenuItem(value: 180, child: Text('180 天（默认）')),
          DropdownMenuItem(value: 365, child: Text('365 天')),
        ],
        onChanged: (value) => _run(
          () => widget.service.setStalePasswordDays(value!),
          success: '健康检查阈值已更新。',
        ),
      ),
      const SizedBox(height: 16),
      FilledButton.icon(
        onPressed: busy || widget.handles[selectedWorkspaceId] == null
            ? null
            : _scanHealth,
        icon: const Icon(Icons.health_and_safety_outlined),
        label: const Text('开始本地检查'),
      ),
      if (health case final findings?) ...[
        const SizedBox(height: 20),
        Text(
          findings.isEmpty ? '未发现风险' : '发现 ${findings.length} 个需关注的条目',
          style: Theme.of(context).textTheme.titleMedium,
        ),
        const SizedBox(height: 8),
        for (final finding in findings)
          ListTile(
            contentPadding: EdgeInsets.zero,
            leading: const Icon(Icons.warning_amber_outlined),
            title: Text(
              selected?.id == selectedWorkspaceId
                  ? '条目 ${finding.entryId.substring(0, 8)}'
                  : '风险条目',
            ),
            subtitle: Text(finding.risks.map(_riskLabel).join('、')),
          ),
      ],
    ],
  );

  Widget _about() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      _heading('关于', 'Authenticator Vault 0.4.0'),
      const ListTile(
        contentPadding: EdgeInsets.zero,
        leading: Icon(Icons.shield_outlined),
        title: Text('离线优先 KDBX 密码与 OTP 工具'),
        subtitle: Text('KDBX 4.1 · Android / iOS / Linux / macOS / Windows'),
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
