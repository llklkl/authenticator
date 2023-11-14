# authenticator
authenticator

## bulid android-arm64 on windows

### 编译 openssl
首先需要出 openssl 的依赖库。由于 windows 上 perl 使用反斜杠作为文件路径分隔符，编译 openssl 时无法正确编译通过，需用到 MSYS2 来编译 android-arm64 的依赖库。

首先克隆 https://github.com/openssl/openssl 库，然后使用下面的脚本编译出 android 适用的 openssl 依赖库。
```shell
#!/bin/bash
# 该脚本需要在MSYS2中运行

NDK_PATH=${ANDROID_NDK_PATH}
export ANDROID_NDK_HOME=$NDK_PATH # openssl 1.* 版本使用
export ANDROID_NDK_ROOT=$NDK_PATH # openssl 3.* 版本使用
export PATH=$NDK_PATH/toolchains/llvm/prebuilt/windows-x86_64/bin:$PATH

mkdir -p ./dist-android-arm64 # 产物路径
perl ./Configure android-arm64  --prefix=$(pwd)/dist-android-arm64 --openssldir=ssl -D__ANDROID_API=24

make -j12 -s
make install -s
```
编译完成后，便会得到下面几个文件夹, `lib` 和 `include` 就是最终需要的。
```shell
$ ls  dist-android-arm64/
bin/
include/
lib/
share/
ssl/
```

### 编译 android 应用

首先要在 `.env` 文件夹下添加一个 `env.json` 文件，内容如下：
```json
{
    "AARCH64_LINUX_ANDROID_OPENSSL_LIB_DIR": "<LIB_PATH>",
    "AARCH64_LINUX_ANDROID_OPENSSL_INCLUDE_DIR": "<INCLUDE_PATH>"
}
```
需要将 `<LIB_PATH>` 和 `<INCLUDE_PATH>` 分别替换为前面编译产物的 `lib` 和 `include` 文件夹的绝对路径。

使用 flutter 编译时，需指定 `--dart-define-from-file` 参数：
```shell
flutter build apk --release --dart-define-from-file=<PATH_TO_env.json>
```

vscode 可以在 `launch.json` 文件夹中加上 `--dart-define-from-file`：
```shell
{
"version": "0.2.0",
    "configurations": [
        {
            "name": "flutter",
            "cwd": "flutter",
            "request": "launch",
            "type": "dart",
            "toolArgs": [
                "--dart-define-from-file=<PATH_TO_env.json>"
            ]
        }
    ]
}
```