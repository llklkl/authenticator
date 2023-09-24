class Tables {
  static const secretTableName = "t_secret";

  static const secretTableScheme = '''
create table if not exists `t_secret`
(
    id        integer not null primary key,
    label     text    not null default '',
    issuer    text    not null default '',
    comment   text    not null default '',
    opt_type  integer not null default 0,
    algorithm integer not null default 0,
    digits    integer not null default 6,
    counter   integer not null default 0,
    period    integer not null default 30,
    secret    text    not null default '',
    otppath   text    not null default ''
);
''';
}
