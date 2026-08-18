import 'package:authenticator_vault/src/app.dart';
import 'package:authenticator_vault/src/features/vault/vault_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('creates a workspace and persists an imported OTP', (
    tester,
  ) async {
    await tester.binding.setSurfaceSize(const Size(420, 900));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final service = _FakeVaultService();
    await tester.pumpWidget(VaultApp(vaultService: service));
    await tester.pumpAndSettle();

    expect(find.text('创建你的第一个 Workspace'), findsOneWidget);
    await tester.tap(find.text('新建 Workspace'));
    await tester.pumpAndSettle();
    final createFields = find.byType(TextField);
    await tester.enterText(createFields.at(0), '个人');
    await tester.enterText(createFields.at(1), 'long master password');
    await tester.enterText(createFields.at(2), 'long master password');
    await tester.tap(find.text('创建'));
    await tester.pumpAndSettle();

    expect(find.text('这个 Workspace 还是空的'), findsOneWidget);
    await tester.tap(find.text('导入 OTP'));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byType(TextField).last,
      'otpauth://totp/Example:alice?secret=TEST',
    );
    await tester.tap(find.text('导入'));
    await tester.pumpAndSettle();

    await tester.tap(find.text('OTP').first);
    await tester.pump(const Duration(milliseconds: 100));

    expect(find.text('Example'), findsOneWidget);
    expect(find.text('alice'), findsOneWidget);
    expect(find.text('123 456'), findsOneWidget);
    expect(service.lastImportedUri, contains('secret=TEST'));

    await tester.pumpWidget(const SizedBox());
  });
}

class _FakeVaultService implements VaultService {
  final workspace = const WorkspaceInfo(
    id: 'personal',
    name: '个人',
    path: '/tmp/personal.kdbx',
  );
  final entries = <VaultEntryItem>[];
  String? lastImportedUri;

  @override
  Future<List<WorkspaceInfo>> loadWorkspaces() async => [];

  @override
  Future<String?> chooseKdbxFile() async => '/tmp/import.kdbx';

  @override
  Future<UnlockedWorkspace> createWorkspace(
    String name,
    String password,
  ) async {
    return UnlockedWorkspace(workspace: workspace, handleId: BigInt.one);
  }

  @override
  Future<UnlockedWorkspace> importWorkspace(
    String name,
    String path,
    String password,
  ) async => UnlockedWorkspace(workspace: workspace, handleId: BigInt.one);

  @override
  Future<BigInt> unlock(WorkspaceInfo workspace, String password) async =>
      BigInt.one;

  @override
  Future<void> lockAll() async {}

  @override
  Future<List<VaultEntryItem>> listEntries(BigInt handleId) async =>
      List.of(entries);

  @override
  Future<void> importOtp(BigInt handleId, String uri) async {
    lastImportedUri = uri;
    entries.add(
      const VaultEntryItem(
        id: 'otp-id',
        type: EntryType.otp,
        title: 'Example',
        username: 'alice',
        url: '',
        hasPassword: false,
        hasOtp: true,
        tags: [],
      ),
    );
  }

  @override
  Future<OtpValue> currentOtp(
    BigInt handleId,
    String entryId,
    DateTime now,
  ) async =>
      const OtpValue(code: '123456', validForSeconds: 30, periodSeconds: 30);

  @override
  Future<void> createEntry(BigInt handleId, VaultEntryDraft draft) async {}

  @override
  Future<void> updateEntry(
    BigInt handleId,
    String entryId,
    VaultEntryDraft draft,
  ) async {}

  @override
  Future<void> deleteEntry(BigInt handleId, String entryId) async {}

  @override
  Future<String> revealNotes(BigInt handleId, String entryId) async => '';

  @override
  Future<String> revealPassword(BigInt handleId, String entryId) async => '';

  @override
  Future<SyncSummary> syncWebDav(
    BigInt handleId,
    String workspaceId,
    WebDavSettings settings,
  ) async => const SyncSummary(attempts: 1, merged: false);
}
