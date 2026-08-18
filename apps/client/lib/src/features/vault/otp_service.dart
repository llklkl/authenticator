import 'package:authenticator_vault/src/rust/api/simple.dart' as native;

abstract interface class OtpService {
  OtpItem importUri(String uri);
  OtpValue current(BigInt handleId, DateTime now);
  void remove(BigInt handleId);
}

class OtpItem {
  const OtpItem({
    required this.handleId,
    required this.issuer,
    required this.account,
  });

  final BigInt handleId;
  final String issuer;
  final String account;
}

class OtpValue {
  const OtpValue({required this.code, this.validForSeconds});

  final String code;
  final int? validForSeconds;
}

class NativeOtpService implements OtpService {
  @override
  OtpItem importUri(String uri) {
    final imported = native.importOtpUri(uri: uri);
    return OtpItem(
      handleId: imported.id,
      issuer: imported.issuer,
      account: imported.account,
    );
  }

  @override
  OtpValue current(BigInt handleId, DateTime now) {
    final value = native.currentOtp(
      handleId: handleId,
      unixSeconds: now.millisecondsSinceEpoch ~/ 1000,
    );
    return OtpValue(
      code: value.code,
      validForSeconds: value.validForSeconds?.toInt(),
    );
  }

  @override
  void remove(BigInt handleId) => native.removeOtp(handleId: handleId);
}
