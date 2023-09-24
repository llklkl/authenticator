import 'dart:io' as io;
import 'dart:ffi' as ffi;

import 'bridge_gen.dart';

const _base = 'authenticatorlib';

// On MacOS, the dynamic library is not bundled with the binary,
// but rather directly **linked** against the binary.
final _dylib = io.Platform.isWindows ? '$_base.dll' : 'lib$_base.so';

final Authenticator Api = AuthenticatorImpl(ffi.DynamicLibrary.open(_dylib));
