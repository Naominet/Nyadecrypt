# CrackProof PE 脱壳与加壳工具

本文档说明 CrackProof PE32/PE32+ 的脱壳、重新加壳、runtime profile、格式细节和验证流程。

本仓库包含：

- `Nyadecrypt.py`：CrackProof PE 脱壳器；
- `Nyaencrypt.py`：将脱壳结果重新编码为 CrackProof 格式的 profile 驱动加壳器。

> 本工具用于已获授权的软件分析、兼容性研究和数据恢复。请确保使用行为符合适用法律及授权范围。

---

## 目录

### 脱壳工具

1. 基本命令
2. 批量处理文件夹
3. AES 表处理
4. 脱壳流程
5. PE32 与 PE32+ 兼容策略
6. 文件数据还原
7. PE 后处理
8. 已修复问题
9. 脱壳限制

### 加壳工具

10. 工具定位
11. 加壳基本命令
12. 输入布局和输出文件
13. 加壳命令行选项
14. Runtime profile 选择
15. 从样本提取 profile
16. 加壳流程
17. .NET DLL 处理
18. 验证方法
19. 常见错误
20. 加壳限制

---

## 1 基本命令

~~~bash
python Nyadecrypt.py <protected_pe>
~~~

输出文件名会在扩展名前插入 .unpack：

~~~text
program.exe  -> program.unpack.exe
module.dll   -> module.unpack.dll
~~~

## 2 批量处理文件夹

输入路径也可以是文件夹：

~~~bash
python Nyadecrypt.py <folder>
~~~

文件夹模式会递归扫描当前文件夹及所有子文件夹，仅检查 `.exe` 和 `.dll` 文件。未检测到 CrackProof 壳的 PE 文件会自动跳过，单个文件失败不会中断后续处理。完成后会显示成功、跳过和失败数量。

程序通过 PE 可选头魔数自动识别 PE32 和 PE32+。

---

## 3 AES 表处理

程序使用以下 AES-256 解密查找表：

- 四张逆向 MixColumns T-table；
- 一张按 32 位字复制的逆 S-box 表；
- 每张表 256 个 uint32；

这些表属于标准 AES 常量，不是目标文件专属数据。gen_aes_tables() 在程序启动时根据有限域运算生成它们。

---

## 4 脱壳流程

整体流程如下：

~~~text
文件尾部加密信息
    -> Stage 1：解密 info 数组
    -> Stage 2：构造并解密 shell 内存映像
    -> Stage 3：定位并处理 SecondStage
    -> Stage 4：定位并处理 ThirdStage
    -> Stage 5：处理 ForthStage
    -> Stage 6：处理 FifthStage
    -> Stage 7：处理 SevenStage
    -> Stage 8：处理 EighthStage
    -> 提取文件数据表、密钥和校验信息
    -> 分块 AES/LFSR/LZ 还原
    -> 修复 PE 头、节表、目录、导入表和入口点
    -> 写出可分析的平坦 PE 映像
~~~

### 4.1 Stage 1：尾部信息

程序从文件尾部读取并解密 8 个 32 位字段。主要内容包括：

- 解密种子；
- 格式标记；
- shell 偏移和大小；
- 数据基址；
- shell 基址；
- 尾部数据大小。

这些字段决定后续内存映像大小和各阶段入口。

### 4.2 Stage 2：shell 解密

程序根据 PE 可选头中的 SizeOfImage 创建缓冲区，将原始数据复制到对应位置，然后对 shell 区域执行第二层解密。

该阶段完成后，缓冲区更接近运行时的 RVA 布局，而不是原始紧凑文件布局。

### 4.3 Stage 3：SecondStage

SecondStage 包含后续阶段所需的：

- 阶段地址和长度；
- 校验值；
- 解密密钥；
- 压缩参数；
- 壳内部成对结构。

PE32+ 路径优先通过稳定特征动态定位内部字段；PE32 路径保留已验证的固定布局，并在关键位置使用候选检测避免单一偏移失效。

### 4.4 Stage 4：ThirdStage

ThirdStage 中包含 key slots、信息表和下一阶段入口。程序通过结构特征寻找 infoTable，再反推出密钥区域，而不是只依赖一个绝对偏移。

信息表中的记录可能表示：

- 解密操作；
- 数据复制操作；
- 下一阶段结构；
- 结束标记。

### 4.5 Stage 5 至 Stage 7

ForthStage、FifthStage 和 SevenStage 逐层执行：

1. 阶段头解密；
2. 校验和确认；
3. 数据解密；
4. 可选自定义流变换；
5. LZ 解压；
6. 提取下一阶段地址、大小和密钥。

SevenStage 的候选密钥与偏移使用结构评分筛选，不再要求密钥区域必须满足过窄的字符特征。

### 4.6 Stage 8：文件数据描述

EighthStage 提供最终文件数据还原所需的信息，包括：

- 压缩块描述；
- 文件级校验数据；
- 文件级 LFSR 参数；
- AES 密钥调度；
- 导入信息；
- 需要清零的区域；
- PE 元数据。

内部偏移会因位数和壳布局变化，因此程序结合候选偏移、范围检查、结构有效性和内容评分进行选择。

---

## 5 PE32 与 PE32+ 兼容策略

程序通过 PE 可选头魔数自动识别位数：

| 魔数 | 类型 |
|---|---|
| 0x10B | PE32 |
| 0x20B | PE32+ |

主要差异：

| 项目 | PE32 | PE32+ |
|---|---|---|
| 指针宽度 | 32 位 | 64 位 |
| Optional Header | PE32 布局 | PE32+ 布局 |
| Thunk 宽度 | 4 字节 | 8 字节 |
| Ordinal 标志 | 32 位高位 | 64 位高位 |
| TLS 目录 | IMAGE_TLS_DIRECTORY32 | IMAGE_TLS_DIRECTORY64 |
| 入口点识别 | 指令特征和代码评分 | 指令特征、布局和代码评分 |
| 壳内部定位 | 固定布局加候选验证 | 动态特征和双布局尝试 |
| 文件级密钥槽 | 使用 PE32 对应槽位 | 使用 PE32+ 对应槽位 |

所有候选地址都应满足：

- 位于映像范围内；
- 长度不会越界；
- 表项数量合理；
- 指向的数据结构符合预期；
- 解密或解压后的内容评分高于其他候选。

---

## 6 文件数据还原

最终数据不是简单复制，而是按描述表逐块处理。典型管线为：

~~~text
读取压缩块
    -> AES-256 解密
    -> 阶段流变换或 LFSR
    -> 可选自定义解密器
    -> LZ 解压
    -> 写入目标 RVA
~~~

### 6.1 AES 解密

AES 使用壳中保存的解密密钥调度。普通轮使用四张 T-table，最后一轮使用逆 S-box 表。

### 6.2 LFSR 与自定义变换

不同布局可能使用不同的 LFSR key 槽和偏移。程序会对候选执行边界、结构和输出内容检查，避免只依赖固定地址。

### 6.3 LZ 解压

解压器支持壳使用的字面量和回溯引用格式。每个块都会验证：

- 源区间有效；
- 目标区间有效；
- 回溯距离合法；
- 输出长度不会超过描述值。

### 6.4 清零区域

壳记录的临时数据、填充区域和运行时工作区会在最终输出前清零，避免将壳状态误认为原程序内容。

---

## 7 PE 后处理

文件数据还原后，还需要将运行时平坦映像整理为可被分析工具或系统加载器理解的 PE。

### 7.1 入口点

入口点优先从已恢复元数据取得；元数据不可靠时，使用代码模式和范围评分选择候选。

候选必须位于可执行节范围内，并具有合理的函数开头或跳转结构。

### 7.2 节表

最终输出采用接近 RVA 的平坦布局。程序会：

- 恢复节数量和节表；
- 重新计算或修正 SizeOfHeaders；
- 使 PointerToRawData 与平坦布局一致；
- 根据映像边界限制 SizeOfRawData；
- 清除多余的旧壳节表项；
- 将文件长度调整到 SizeOfImage。

### 7.3 导入表

导入恢复支持两条路径：

1. 原始 Import Directory 仍有效时，原位解密和修复；
2. Import Directory 无效时，根据 IAT、字符串和 thunk 结构重建 IDT。

导入恢复会同时处理：

- DLL 描述符；
- OriginalFirstThunk；
- FirstThunk；
- 名称导入；
- ordinal 导入；
- Import Directory；
- IAT Directory。

### 7.4 数据目录

程序对常见数据目录执行防御性校验：

- Import；
- IAT；
- Base Relocation；
- Resource；
- TLS；
- CLR/COR20。

无效目录不会原样保留，以免系统加载器在执行入口点之前崩溃。

### 7.5 .NET 元数据

对于托管 PE，程序会验证并恢复：

- COR20 Header；
- CLR metadata RVA 和大小；
- metadata 签名；
- 托管入口信息；
- 相关数据目录。

如果目录存在但结构为空或明显伪造，会清除无效目录；如果有效 metadata 可以从恢复数据中定位，则重建正确引用。

---

## 8 已修复问题

旧文档中的逐文件、逐日期调试记录已经合并为以下通用问题表。

### 8.1 阶段定位和候选选择

| 问题 | 原因 | 当前处理 |
|---|---|---|
| SecondStage 内部偏移在不同布局中变化 | 只使用固定偏移 | PE32+ 使用特征锚点和结构验证；PE32 使用固定布局加候选校验 |
| ThirdStage 信息表无法定位 | 假设信息表位于固定地址 | 扫描合法记录组合并反推密钥区域 |
| EighthStage key 偏移变化 | 只尝试单一候选 | 扩展候选集合，并按范围和解密结果评分 |
| SevenStage key 被错误过滤 | 使用过窄的 ASCII 特征 | 移除字符集硬过滤，改用结构和输出有效性 |
| 指针候选被错误排除 | 对合法高地址设置了过低上限 | 统一使用映像范围和目标结构验证 |
| 布局识别误判 | 通过单字段提前决定 Layout A/B | 对两个布局分别解析和评分，选择完整有效结果 |

### 8.2 AES、LFSR 和文件块处理

| 问题 | 原因 | 当前处理 |
|---|---|---|
| AES 表文件缺失导致无法运行 | 依赖五个外部二进制表 | 启动时生成标准 AES 表，旧文件仅作可选兼容 |
| PE32 文件级 LFSR 定位失败 | 偏移列表和选择条件不足 | 增加候选并验证解密后的块结构 |
| PE32+ 文件级 LFSR 选错 | 多个候选都满足浅层条件 | 对完整输出、边界和后续结构联合评分 |
| 文件校验循环越界 | 结束条件没有限制表范围 | 增加显式长度、计数和地址检查 |
| 解压回溯越界 | 损坏记录可能产生非法距离 | 验证源、目标、距离和最大输出长度 |

### 8.3 decrypt_data8 判定

| 问题 | 原因 | 当前处理 |
|---|---|---|
| 不同文件使用不同页密钥公式 | 固定使用一种公式 | 同时评估多个标准候选和“不变换”候选 |
| PE32 自动检测效果不稳定 | 仅比较整个页面的简单字节统计 | 结合实际变换位置、代码特征和结构评分 |
| 已是明文的页面被二次变换 | 只要候选略优就应用 | 要求最佳候选相对基线具有明显优势 |
| 真正需要变换的页面被跳过 | 使用固定差值阈值 | 统计算法实际修改位置的命中率，而不是无关字节 |
| 选择错误后入口代码损坏 | 决策与入口点验证分离 | 将入口代码合理性纳入候选判断和后处理检查 |

### 8.4 导入表和元数据

| 问题 | 原因 | 当前处理 |
|---|---|---|
| 导入表被重复重建 | 原位恢复后仍进入 fallback | 两条路径互斥，成功后停止二次处理 |
| Import RVA 指向错误区域 | 仅信任单一 metadata 字段 | 结合节范围、描述符和 thunk 有效性选择 |
| IAT Directory 与真实 IAT 不一致 | 只更新 Import Directory | 同步重建或修正 IAT Directory |
| 名称导入和 ordinal 导入混淆 | 未按位数处理 ordinal 标志 | 分别使用 PE32/PE32+ thunk 宽度和标志 |
| DLL 与 EXE 目录处理不一致 | 使用统一但错误的默认值 | 保留文件类型，并按实际目录有效性修复 |
| 元数据布局变化导致错读 | 假设 metadata 只有一种排列 | 尝试已知布局并使用结构完整性评分 |
| Subsystem 被壳数据覆盖 | 直接继承不可靠字段 | 恢复目标 PE 的原始 Subsystem |

### 8.5 PE 头和加载器兼容性

| 问题 | 原因 | 当前处理 |
|---|---|---|
| 输出节的 raw offset 与平坦映像不一致 | 沿用紧凑文件布局字段 | 将 raw offset/size 修正为与 RVA 平坦布局一致 |
| 节表残留保护层条目 | 只覆盖目标节而未清理剩余项 | 清零多余节表项并修正节数量 |
| Base Relocation 目录指向伪数据 | 无条件保留不可靠 metadata | 验证重定位块；无效时清除目录 |
| 强制 ASLR 与无效重定位组合 | DllCharacteristics 与目录不一致 | 根据恢复结果清理不兼容标志 |
| TLS 目录指向全零结构 | 加载器在入口点前解引用空地址 | 校验 TLS 字段；全零或越界结构会清除目录 |
| COR20 目录指向空或伪 Header | 加载器错误识别为托管映像 | 校验 Header 和 metadata；无效时清除，能恢复时重建 |
| 托管 metadata 丢失 | 只恢复 COR20 外层目录 | 同步恢复 metadata RVA、大小和签名 |
| 入口点落入保护层或非代码区 | 直接使用不可靠字段 | 结合可执行节范围、指令模式和 metadata 选择 |
| 文件长度与 SizeOfImage 不一致 | 解密后未统一裁剪或扩展 | 写出前按映像大小补零或截断 |

---

## 9 脱壳限制
- 输出采用便于分析的平坦 RVA 布局，不保证与原始未保护文件的紧凑磁盘布局逐字节一致。
- 导入表重建可能改变导入节的排列，但不应改变实际导入语义。
- 无效 TLS、Reloc 或 CLR 目录可能被安全清零；这属于加载器兼容性修复，而不是原样保留。
- 对新布局增加支持时，应优先增加结构验证和候选评分，不应继续堆叠未经验证的文件专属绝对偏移。

---

## 10 工具定位

`Nyaencrypt.py` 将脱壳得到的 PE32/PE32+ 程序重新编码为 CrackProof 数据链，包括：

- `KONN` 格式标记；
- Data1 和 Data2；
- 阶段数据与 `compressedInfo`；
- AES-256、LFSR 和可选 LZ 压缩；
- 文件校验、导入信息和 PE 元数据。

输出不是旧的 `.nyapck` 自定义加载器，而是当前 [Nyadecrypt.py](Nyadecrypt.py) 可以解析的 CrackProof 格式。

本工具目前是 **profile 驱动的 CrackProof 重打包器**。profile 提供壳运行时、阶段布局和可复用 stub，目标程序由工具重新编码。它还不是可以脱离原始壳样本、为任意 PE 自动生成完整 native stub 的 donorless 编译器。

---

## 11 加壳基本命令

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

## 12 输入布局和输出文件

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

## 13 加壳命令行选项

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

## 14 Runtime profile 选择

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

## 15 从样本提取 profile

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

## 16 加壳流程

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

### 16.1 Data1 和 Data2

Data1 保存解密种子、格式标记、shell/数据范围和阶段入口所需字段，其中包含 `KONN` 标记。Data2 保存后续阶段使用的 shell 数据和元数据。

### 16.2 文件块编码

每个文件块按相反顺序恢复为壳要求的磁盘形式：

~~~text
明文程序块
    -> 可选 LZ 压缩
    -> 逆向 LFSR 变换
    -> AES-256-CBC 加密
    -> 写入 compressedInfo 指向的数据区
~~~

file-decrypt 使用的正向变换、AES 密钥调度和压缩符号表从 profile 的已解析壳上下文中取得，工具不会把这些内容替换为自定义容器。

### 16.3 Native overlap

CrackProof 的 native 重打包使用 overlap 设计，使完整目标映像仍可通过 `compressedInfo` 重建，同时在入口点前由壳恢复执行环境。`--no-overlap` 会把可打包范围截到 info3，目标超出部分会被丢弃，因此只应在分析调试时使用。

### 16.4 PE32 和 PE32+

工具支持：

| 魔数 | 类型 |
|---|---|
| `0x10B` | PE32 |
| `0x20B` | PE32+ |

可选头、thunk、导入目录、重定位和镜像尺寸均按位数解析。不支持的 optional-header 魔数会被拒绝。

---

## 17 .NET DLL 处理

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

## 18 验证方法

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

## 19 常见错误

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

## 20 加壳限制

- 工具仍是 profile 驱动的 CrackProof 重打包器，不是完整的 donorless native-stage 编译器。
- 新壳变体仍可能需要从其样本提取新的 runtime profile。
- 默认未提供 native DLL 和 managed EXE profile；这两类输入会 fail-closed。
- 托管 DLL 必须与 profile 的节布局兼容，且 COR20/BSJB metadata 必须有效。
- 纯 IL 程序、混合模式程序和新版 native stage 可能需要额外兼容工作。
- `--no-overlap`、`--no-imports` 和 `--no-verify` 只用于调试，不应作为正常加壳流程。
- 字节级 SHA-256 回环可作为强验证，但不能替代目标环境的加载和运行测试。

---

Copyright (C) 2026 Nyadecrypt contributors.
