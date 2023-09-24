class Secret {
  Secret(
      {required this.otpType,
      required this.algorithm,
      this.digits = 6,
      this.counter = 0,
      this.period = 30,
      this.label = "",
      this.issuer = "",
      this.comment = "",
      this.otpPath = "",
      this.secret = ""});

  int id = 0;
  int otpType;
  int algorithm;
  int digits;
  int counter;
  int period = 30;
  String label = "";
  String issuer = "";
  String comment = "";
  String otpPath = "";
  String secret;

  Map<String, dynamic> toMap() => {
        "label": label,
        "issuer": issuer,
        "comment": comment,
        "opt_type": otpType,
        "digits": digits,
        "algorithm": algorithm,
        "counter": counter,
        "period": period,
        "otppath": otpPath,
        "secret": secret,
      };

  Secret.fromMap(Map<String, dynamic> map)
      : id = map["id"],
        label = map["label"],
        issuer = map["issuer"],
        comment = map["comment"],
        otpType = map["opt_type"],
        digits = map["digits"],
        algorithm = map["algorithm"],
        counter = map["counter"],
        period = map["period"],
        otpPath = map["otppath"],
        secret = map["secret"] {
    if (period == 0) period = 30;
  }
}
