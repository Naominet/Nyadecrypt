# CrackProof PE 加壳工具

本文档说明 `Nyaencrypt.py` 的使用方式、runtime profile、CrackProof 数据链、托管 DLL 处理和验证流程。

> 本工具用于已获授权的软件分析、兼容性研究和数据恢复。请确保使用行为符合适用法律及授权范围。

脱壳工具和完整脱壳流程见 [README.md](README.md)。

---

## 目录
1. 工具定位
2. 基本命令
3. 输入布局和输出文件
4. 命令行选项
5. Runtime profile 选择
6. 从样本提取 profile
7. 加壳流程
8. .NET DLL 处理
9. 验证方法
10. 常见错误
11. 当前限制

---

## 1 工具定位

`Nyaencrypt.py` 将脱壳得到的 PE32/PE32+ 程序重新编码为 CrackProof 数据链，包括：

- `KONN` 格式标记；
- Data1 和 Data2；
- 阶段数据与 `compressedInfo`；
- AES-256、LFSR 和可选 LZ 压缩；
- 文件校验、导入信息和 PE 元数据。

输出不是旧的 `.nyapck` 自定义加载器，而是当前 [Nyadecrypt.py](Nyadecrypt.py) 可以解析的 CrackProof 格式。

本工具目前是 **profile 驱动的 CrackProof 重打包器**。profile 提供壳运行时、阶段布局和可复用 stub，目标程序由工具重新编码。它还不是可以脱离原始壳样本、为任意 PE 自动生成完整 native stub 的 donorless 编译器。

---

## 2 基本命令

~~~bash
python Nyaencrypt.py <unpacked_pe>
python Nyaencrypt.py <unpacked_pe> --lz
python Nyaencrypt.py <unpacked_pe> -o <packed_pe>
~~~

默认输出文件名会在扩展名前插入 `.packed`：

~~~text
program.unpack.exe  -> program.unpack.packed.exe
module.unpack.dll   -> module.unpack.packed.dll
~~~

示例：

~~~bash
python Nyaencrypt.py SDDT115Assembly-CSharp.unpack.dll --lz
python Nyaencrypt.py SDDT155amdaemon.unpack.exe --lz
~~~

建议保留 `--lz`。不加 `--lz` 时仍会执行 LFSR 和 AES 编码，只是文件块按未压缩形式保存；加 `--lz` 后，能在压缩后变小的块会使用真实 LZ 编码。

---

## 3 输入布局和输出文件

工具接受两种输入：

| 布局 | 含义 |
|---|---|
| `file` | 普通磁盘 PE，节数据位于实际文件偏移 |
| `flat` | 平坦 RVA 映像，文件偏移与 RVA 对齐 |
| `auto` | 自动检测，默认值 |

~~~bash
python Nyaencrypt.py target.exe --input-layout auto
python Nyaencrypt.py target.exe --input-layout file
python Nyaencrypt.py target.exe --input-layout flat
~~~

通常应使用 `auto`。`Nyadecrypt.py` 生成的 `.unpack.exe` 和 `.unpack.dll` 通常为平坦 RVA 布局，`auto` 会识别并转换。仅当自动识别不适用时，才手工指定布局。

输出文件保持输入文件的 PE32/PE32+ 类型、DLL/EXE 标志和节布局。对于 native 跨布局重打包，工具会在文件尾部写入供 `Nyadecrypt.py` 恢复目标 PE 头使用的 `CPXSECT` 元数据；Windows 加载器会忽略该 overlay。

---

## 4 命令行选项

~~~text
python Nyaencrypt.py [-h] [-o OUTPUT] [--lz] [--no-overlap] [--no-verify]
                     [--no-imports] [--aes-dir AES_DIR]
                     [--input-layout {auto,flat,file}]
                     target [profile]
~~~

| 选项 | 作用 |
|---|---|
| `target` | 待加壳的 PE32/PE32+ 文件 |
| `profile` | 可选，显式指定 runtime profile；省略时自动选择 |
| `-o`, `--output` | 指定输出路径 |
| `--lz` | 对可缩小的数据块启用真实 LZ 压缩 |
| `--input-layout` | 输入布局：`auto`、`flat` 或 `file` |
| `--no-overlap` | 只调试用；将程序限制在 info3，可能丢弃尾部 |
| `--no-verify` | 跳过加壳后的内部回环验证，不建议使用 |
| `--no-imports` | 跳过目标导入名称的 Data7 混淆，仅用于调试 |
| `--aes-dir` | 指定旧式 AES 表目录；默认直接在代码中生成标准表 |

正常使用不要添加 `--no-overlap`、`--no-verify` 或 `--no-imports`。这些选项用于定位格式问题，可能生成不完整的调试产物。

---

## 5 Runtime profile 选择

省略第二个位置参数时，工具按 PE 类型自动选择 profile：

| 目标类型 | 自动选择 | 当前状态 |
|---|---|---|
| .NET DLL，存在 CLR 目录 | `stub_profile_dotnet_dll.bin` | 已提供，要求节布局兼容 |
| Native EXE，无 CLR 目录 | `stub_profile.bin` | 已提供 |
| Native DLL | `stub_profile_native_dll.bin` | 仓库尚未提供，默认拒绝 |
| Managed EXE，存在 CLR 目录 | 无默认 profile | 默认拒绝，避免误用 native EXE profile |

也可以显式指定 profile：

~~~bash
python Nyaencrypt.py target.dll sample.profile.bin --lz -o target.packed.dll
~~~

profile 必须与目标文件的架构、DLL/EXE 类型、CrackProof 版本和关键节布局匹配。对 .NET DLL，工具会执行 fail-closed 校验；错误的 profile 或不兼容布局会被拒绝，不会静默生成一个看似 native/C++ 的损坏 DLL。

---

## 6 从样本提取 profile

如果自动 profile 不适用于某个壳变体，可以从一个可解析的带壳样本提取 profile：

~~~bash
python Nyaencrypt.py extract <packed_sample> <profile.bin>
~~~

示例：

~~~bash
python Nyaencrypt.py extract SDDT115Assembly-CSharp.dll SDDT115Assembly-CSharp.profile.bin
python Nyaencrypt.py SDDT115Assembly-CSharp.unpack.dll SDDT115Assembly-CSharp.profile.bin --lz -o SDDT115Assembly-CSharp.repacked.dll
~~~

提取 profile 不等于实现对任意输入完全免依赖加壳。profile 仍来自具体 CrackProof 样本，并复用了该样本的运行时布局和 stub 数据。优先选择与目标程序具有相同架构、类型、节布局和壳版本的样本。

profile 为可信二进制数据，加载时使用 Python pickle。不要加载来源不明或被篡改的 profile。

查看提取命令帮助：

~~~bash
python Nyaencrypt.py extract --help
~~~

---

## 7 加壳流程

工具执行的主要步骤如下：

~~~text
读取并验证目标 PE
    -> 选择 runtime profile
    -> 将目标转换为 file-offset == RVA 的映像
    -> 构造目标程序区和 compressedInfo
    -> 可选 LZ 压缩
    -> 逆向 LFSR 流变换
    -> AES-256-CBC 加密文件块
    -> Data7 混淆导入名称
    -> 生成 Data1 的 KONN/info 数据
    -> 生成 Data2 shell 和阶段数据链
    -> 重建 packed PE 头、节表和加载器可见数据
    -> 内部解析验证并写出文件
~~~

### 7.1 Data1 和 Data2

Data1 保存解密种子、格式标记、shell/数据范围和阶段入口所需字段，其中包含 `KONN` 标记。Data2 保存后续阶段使用的 shell 数据和元数据。

### 7.2 文件块编码

每个文件块按相反顺序恢复为壳要求的磁盘形式：

~~~text
明文程序块
    -> 可选 LZ 压缩
    -> 逆向 LFSR 变换
    -> AES-256-CBC 加密
    -> 写入 compressedInfo 指向的数据区
~~~

file-decrypt 使用的正向变换、AES 密钥调度和压缩符号表从 profile 的已解析壳上下文中取得，工具不会把这些内容替换为自定义容器。

### 7.3 Native overlap

CrackProof 的 native 重打包使用 overlap 设计，使完整目标映像仍可通过 `compressedInfo` 重建，同时在入口点前由壳恢复执行环境。`--no-overlap` 会把可打包范围截到 info3，目标超出部分会被丢弃，因此只应在分析调试时使用。

### 7.4 PE32 和 PE32+

工具支持：

| 魔数 | 类型 |
|---|---|
| `0x10B` | PE32 |
| `0x20B` | PE32+ |

可选头、thunk、导入目录、重定位和镜像尺寸均按位数解析。不支持的 optional-header 魔数会被拒绝。

---

## 8 .NET DLL 处理

托管 DLL 不能只把 CLR 数据放进压缩层。Windows 和 .NET 反射工具需要在壳运行前从加载器可见的原始节中读取 COR20 和 metadata，因此工具会：

1. 根据 CLR 目录和 DLL 标志自动选择托管 DLL profile；
2. 保留 profile 要求的加载器可见 raw section 范围；
3. 将目标的 COR20 Header 写入映射后的原始节；
4. 将 BSJB metadata 写入其 RVA 对应的原始数据；
5. 校验 DLL/EXE 标志、CLR 目录、COR20、metadata 签名和大小；
6. 拒绝不兼容的节布局，而不是输出损坏的伪 native DLL。

加壳后的 DLL 可用 PowerShell 检查程序集名：

~~~powershell
[Reflection.AssemblyName]::GetAssemblyName((Resolve-Path .\module.packed.dll))
~~~

成功时应返回目标的程序集名称，而不是 `BadImageFormatException`。

---

## 9 验证方法

默认情况下，工具会在写出文件后重新解析输出，并验证 embedded program 能恢复到目标程序区。导入节允许存在差异，因为导入名称在解码映像中处于 Data7 混淆状态。

成功时会显示类似信息：

~~~text
VERIFY OK: embedded program reconstructs to the target (import-dir diffs only)
~~~

也可以执行完整脱壳回环：

~~~bash
python Nyaencrypt.py module.unpack.dll --lz -o module.packed.dll
python Nyadecrypt.py module.packed.dll
~~~

预期生成：

~~~text
module.packed.unpack.dll
~~~

比较输入和回环输出的 SHA-256：

~~~powershell
Get-FileHash .\module.unpack.dll -Algorithm SHA256
Get-FileHash .\module.packed.unpack.dll -Algorithm SHA256
~~~

两个哈希一致，说明该样本在当前 profile 和布局下完成了严格字节回环。

截至 2026-09-23，在 `F:\0000amdaemon\crackproof` 的 95 个带壳样本上，95 个均能完成脱壳、重新加壳和再次脱壳；其中 94 个 SHA-256 完全一致。唯一未完全一致的 EXE 为 `SDER142InitialD0_DX11_Nu_CHN.exe`，文件大小和程序流程一致，但在 `.rdata` 偏移 `0x160FC62` 处有 2 字节差异：

~~~text
原始带壳文件：35 06
恢复文件：    00 00
~~~

---

## 10 常见错误

| 错误信息 | 含义 | 处理方式 |
|---|---|---|
| `target is not a PE file` | 输入缺少 MZ/PE 签名 | 确认输入是有效 PE |
| `unsupported optional-header magic` | 不是 PE32/PE32+，或头已损坏 | 修复或重新脱壳 |
| `managed EXE needs ... profile` | 没有托管 EXE 的默认 runtime profile | 提取兼容 profile 并显式传入 |
| `profile not found for native DLL` | 缺少 native DLL profile | 提取兼容 profile 并显式传入 |
| `managed PE layout is incompatible` | 目标节布局与托管 DLL profile 不匹配 | 使用同布局样本重新提取 profile |
| `managed target became native` | 输出丢失加载器可见 CLR 信息 | 使用正确的托管 DLL profile，不要强制 native profile |
| `packed CLR metadata ...` | COR20/BSJB 不匹配或不可见 | 检查 profile、目标 metadata 和节布局 |
| `target image ... exceeds ... info3` | 使用 `--no-overlap` 时目标超出可打包范围 | 去掉 `--no-overlap` 或换用更大的兼容 stub |
| `VERIFY FAIL` | 内部回环验证发现目标程序区不一致 | 不要使用该输出，检查 profile 和布局 |

退出码 `0` 表示命令和默认验证成功；`2` 通常表示输入、profile 或格式校验失败；`130` 表示用户中断。

---

## 11 当前限制

- 工具仍是 profile 驱动的 CrackProof 重打包器，不是完整的 donorless native-stage 编译器。
- 新壳变体仍可能需要从其样本提取新的 runtime profile。
- 默认未提供 native DLL 和 managed EXE profile；这两类输入会 fail-closed。
- 托管 DLL 必须与 profile 的节布局兼容，且 COR20/BSJB metadata 必须有效。
- 纯 IL 程序、混合模式程序和新版 native stage 可能需要额外兼容工作。
- `--no-overlap`、`--no-imports` 和 `--no-verify` 只用于调试，不应作为正常加壳流程。
- 字节级 SHA-256 回环可作为强验证，但不能替代目标环境的加载和运行测试。

---

Copyright (C) 2026 Nyadecrypt contributors.