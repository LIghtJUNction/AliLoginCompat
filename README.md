# AliLoginCompat（实验版）

一个 LSPosed / Vector 模块：将淘宝明确拒绝访问的全屏页面收起为可关闭的小悬浮球，并提供匹配版本安全库的候选 WUA 状态改写实验。

**当前是兼容性实验，尚未证明能够解决自动退登。** 这七个字节的完整语义仍未知，全部置零不等于已获得正常设备的状态。服务器仍可能拒绝请求。模块保留客户端退登逻辑，不修改账号、设备标识或服务器凭证。

## 淘宝拒绝页悬浮球

默认开启，仅匹配 `https://bixi.alicdn.com/punish/…?action=deny`。其他验证页走原流程。真机确认的当前路径为 `FCDuplexFilter → FCComponent → StrategyCenter → ContainerActivity`。模块在页面启动入口收起全屏页面，通过原 SDK 本地广播回传与关闭页面相同的 CANCEL 结果。旧 MTOP 入口另保留原子去重和超时失败处理。业务请求仍可能失败，收起提示不会恢复被服务器拒绝的业务。

- 小球使用淘宝自己的附属窗口，不需要系统悬浮窗权限，不抢焦点，窗口外的触摸继续交给原界面。
- 拖动圆点移动位置，点“×”后持续隐藏，重启淘宝后仍隐藏；设置中关闭再打开悬浮球可恢复；切到其他应用时移除。
- 在模块设置中关闭“将淘宝拒绝页收起为小悬浮球”，重启淘宝后可恢复原页面。
- Java 字段或方法不匹配时保留原流程，不伪造验证结果。

真机已确认悬浮球显示、首页保持可见、附属窗口具有 NOT_FOCUSABLE / NOT_TOUCH_MODAL 标志。收到关闭失效反馈后，已修复重复创建窗口打断触摸的问题，并保存关闭状态；用户已复测确认点关闭后不再出现；跨进程重启的持久隐藏尚待单独复测。

## WUA 实验做了什么

1. 仅在 `com.taobao.taobao`、`com.taobao.idlefish` 的主进程加载。
2. 使用 [LSPosed 官方 Native Hook API](https://github.com/LSPosed/LSPosed/wiki/Native-Hook)，等待目标安全库加载。
3. 校验整个库文件 SHA-256、函数所在可执行段，以及原始指令的 SHA-256。未知或已被其他钩子修改的版本保持原样。
4. 观察安全库的缓冲区追加函数。只有长度、标记和尾部全部匹配各应用对应的 18 字节形状时，才可能改写：

   ```text
   闲鱼：11 ?? ?? ?? ?? ?? ?? ?? 22 33 00 00 00 00 00 00 00 00
   淘宝：{00|10} ?? ?? ?? ?? ?? ?? ?? 22 33 00 00 00 00 00 04 00 00
   ```

5. 开启实验时，将中间七个候选状态字节置零，保留其他字节、长度和源缓冲区。后续 WUA 编码、压缩和加密仍由应用原安全库完成。

没有把设备密钥、会话、真实请求样本或任何应用安装包放入本仓库。模块不需要这些密钥。日志仅包含版本校验结果、模式和计数，不输出 WUA、token 或 cookie。

## 支持范围

仅构建 `arm64-v8a`，需要具有 Native Hook 支持的 LSPosed 兼容框架。模块需要支持新 XSharedPreferences 的框架，最低声明版本 93。开发设备使用 [Vector](https://github.com/JingMatrix/Vector)。

| 应用 / 安全库 | 原生 append 偏移 | 当前证据 |
| --- | --- | --- |
| 闲鱼 / `libsgmainso-6.7.260202.so` | `0x14ed38` | 状态块复制位置及其与 WUA 返回值的关系已实测；用户反馈安装后登录恢复，因果对照尚未完成 |
| 淘宝 / `libsgmainso-6.8.260901.so` | `0x14dc40` | 真机原生钩子已安装；用户反馈仍显示访问被拒绝，尚未修复 |

完整文件与指令指纹见 [`profiles.inc`](app/src/main/cpp/profiles.inc)。不匹配时不会尝试猜地址。应用版本号相同也不保证安全库相同。

## 使用

1. 安装 APK，在框架中启用模块，只勾选淘宝和闲鱼；模块设置应用自身可加入作用域以使用框架配置服务。
2. 打开 AliLoginCompat，分别设置拒绝页悬浮球和候选状态改写。两应用改写开关和悬浮球独立。淘宝改写默认关闭。关闭某应用改写且关闭诊断后，该应用完全跳过原生钩子。
3. 结束并重新打开目标应用，再手动登录。
4. 验证登录后刷新个人页、访问需要登录的业务，并保持一段时间。看到头像不代表服务器会话有效。
5. 停用模块并结束目标进程可移除钩子；模块不会修改目标 APK 或清除其数据。

如果配置服务未生效，目标进程跳过原生改写。配置只在进程启动时读取，修改后需要重新打开目标应用。

### 可选的本地诊断

设置中的诊断开关默认关闭。启用后，目标应用启动时会在后台调用一次现有 `SecurityGuardManagerWraper.getWUA()`。淘宝还调用两次现有 `getSecurityBodyDataEx(..., purpose=8, appEnv)` 以核对 MiniWUA 路径与缓存；不调用登录接口。诊断还会记录追加调用计数，以及最多 32 个短候选缓冲区的原始字节。样本保存于目标应用私有缓存 `alilogincompat-probe.json`，用于在自有设备上核对改写计数及报文格式。

该文件可能包含设备指纹材料；不要上传到 Issue。诊断结束后关闭开关并删除该文件。公开反馈只需要应用 / 安全库版本、是否匹配、计数和脱敏后的结果。

### 请求状态观察（alpha.9）

设置中的“仅记录淘宝请求状态码”（`trace_status`）默认关闭，仅观察淘宝主进程已有响应。它在 `tb.ev8.c(tb.w4j)` 的入口和应用读取 `MtopResponse.getRetCode()` 后记录状态，不创建网络请求，不调用登录或安全参数生成方法，也不修改原方法的返回值或异常。

这一开关与原生实验功能独立。仅打开它、并保持淘宝改写、probe、trace_business、env_trace、env_compat 关闭时，日志应同时出现：

```text
status trace ready filter_entry=true limit=128 native=false
loaded package=com.taobao.taobao mode=ui-only native_hooks=skipped ... status_trace=true
```

每条记录只包含阶段、单调时间、进程内临时响应编号、校验后的 API 名、HTTP 状态和规范化 MTOP 错误码。同一响应可用编号关联两个阶段；重复状态去重，每进程最多 128 条。它不记录 URL、查询参数、请求头、正文、错误文案、签名或凭证。

`filter_entry` 时的错误码可能尚未填入，此时记录 `UNAVAILABLE`，不能据此认定请求成功。`filter_entry=false` 表示内部过滤器未匹配；已达到记录上限或没有新事件，也不能视为业务恢复。诊断结束后关闭开关并重新打开淘宝。

2026-11-17 真机确认 alpha.9 的过滤器和 getter 观测均命中，原生钩子保持跳过。购物车接口 `mtop.trade.query.bag` 仍返回 HTTP 419，并出现 `ANDROID_SYS_API_41X_ANTI_ATTACK`；另有首页请求记录到 `FAIL_SYS_USER_VALIDATE`。这是新的诊断能力，尚未恢复被拒绝的淘宝业务。

### USB 状态兼容实验（alpha.16）

`usb_compat` 默认关闭。开启后仅将淘宝内 `USB_STATE` 广播副本的 `connected` 改为 `false`，使 `SecurityBodyAdapter.doAdapter(10)` 返回 `"0"`；其他广播字段、电池状态和原生钩子均不因此改变。参考实现为 [DuckDroid2 的同版本环境](https://github.com/djskncxm/DuckDroid2/blob/8fd6f73176957a5493cbff4c420a4d8166bbd959/code/user_code/taobao_case/taobao_env.cpp)。

真机已确认原始 `connected=true`、修改后 `doAdapter(10)=0`，但同一购物车请求仍返回 HTTP 419，因此该开关不是已验证的修复。离线 purpose=8 对照使用相同初始状态、时间和随机种子，同设置复跑的 18 字节状态完全一致；USB 切换只稳定改变第 5 字节的 `0x01` 位及第 8/9 字节的派生校验。`adb_enabled` 对照的 18 字节状态没有差异。这些结果说明字段进入安全输出与服务器接受请求是不同问题，不能据此推断服务端规则。

## 本地构建和验证

需要 JDK 21、Android SDK 36、NDK `27.1.12297006`、CMake `3.22.1`。在 `local.properties` 设置 `sdk.dir`，或设置 Android SDK 环境变量。

```sh
./gradlew :app:assembleRelease
g++ -std=c++17 -Wall -Wextra -Werror tests/policy_test.cpp -o /tmp/alilogincompat-policy-test
/tmp/alilogincompat-policy-test
javac -d /tmp/alilogincompat-ui-tests app/src/main/java/io/github/lightjunction/alilogincompat/DenyLocationPolicy.java tests/DenyLocationPolicyTest.java
java -cp /tmp/alilogincompat-ui-tests io.github.lightjunction.alilogincompat.DenyLocationPolicyTest
javac -d /tmp/alilogincompat-status-tests app/src/main/java/io/github/lightjunction/alilogincompat/MtopStatusPolicy.java tests/MtopStatusPolicyTest.java
java -cp /tmp/alilogincompat-status-tests io.github.lightjunction.alilogincompat.MtopStatusPolicyTest
javac -d /tmp/alilogincompat-usb-tests app/src/main/java/io/github/lightjunction/alilogincompat/UsbCompatPolicy.java tests/UsbCompatPolicyTest.java
java -cp /tmp/alilogincompat-usb-tests io.github.lightjunction.alilogincompat.UsbCompatPolicyTest
```

Release 构建产生未签名 APK，请用自己的密钥签名。签名密钥、密码、构建产物和诊断样本均不应提交。日常验证在本地完成，本仓库不配置自动 CI。

宿主测试覆盖匹配边界、错误标记拒绝、长度限制、改写范围和源缓冲区不变性。它不能证明真机注入或服务器登录效果，后两者必须分别验证。

## 状态

- 拒绝页悬浮球：真机显示已确认，精确 URL 匹配测试通过；用户已确认关闭后不再出现。
- 核心改写逻辑：已实现。
- 本地 Release 构建、APK 签名和宿主边界测试：通过。
- Vector 真机：淘宝主进程确认原生钩子安装成功；alpha.1 的私有诊断确认追加函数执行、生成 WUA，但因淘宝结构不同未改写；alpha.2 增加独立结构匹配，真机确认 matched=1 / rewritten=1；冷启动仍出现访问被拒绝，因此这处改写不足以修复淘宝。
- 闲鱼：用户反馈安装后恢复登录；未完成停用/启用对照，不宣称已证明因果关系。
- 淘宝：仍存在 HTTP 419 / FAIL_SYS_USER_VALIDATE / action=deny 拦截，尚未修复。关闭抓包、按 UID 直连、短时停止透明代理及使用已验证 Wi-Fi 后，冷启动仍能出现拒绝页；实际关闭 ADB 并停止 adbd 的对照中，购物车也仍返回 HTTP 419。`mid_sen_wl_0_400009` 明确单列购物车等敏感 API，但同状态推荐成功/购物车拒绝及离线 API 对照均未给出可修复的环境位，服务端具体规则未知。
- 服务器风控规则：未知。这个实验不宣称恢复或伪造正常风控结论。

## 许可

本项目采用 Apache-2.0。SHA-256 实现来自 Brad Conte 的 public-domain 项目，固定版本和来源见 [`third_party/NOTICE`](app/src/main/cpp/third_party/NOTICE)。Gradle Wrapper 来自 Gradle（Apache-2.0）。

本地 purpose=8 诊断：两次返回均为 209 字符，各自增加 4 次追加操作，当前 18 字节候选块匹配/改写增量均为零。该结果只描述此独立 MiniWUA 调用，不宣称覆盖了统一签名 70102 的全部业务路径。

仅 UI 对照：淘宝关闭改写与诊断后，确认 native_hooks=skipped，原生 append 函数运行时 64 字节指纹与原版一致。用户反馈购物车、搜索、详情仍失败；抓包确认购物车及两个详情接口收到新的 HTTP 419。该对照不排除其他模块、设备状态或历史服务端判定。


### Actual business-call diagnostics (alpha.4)

The [verified 70102 wrapper analysis](docs/taobao-70102-analysis.md) distinguishes local argument/output errors, the identified fallback, form encoding, and server rejection. It also clarifies Ghidra addresses versus runtime ELF offsets.

Alpha.6 also observes at most 64 existing `doCommandNative` calls for commands 20102/70102/70103. It records command nesting, thread, Java stack, append positions and output digests in a separate private `alilogincompat-command-trace.jsonl` file. The bridge is resolved from the actual SDK proxy/router loader; global class-loader methods are not hooked. Arguments and results remain unchanged; raw command arguments and tokens are not saved. Disable business tracing and restart Taobao after sampling, and remove both diagnostic files when their verified local copies are retained.

`trace_business` is a separate opt-in switch, off by default, for the pinned Taobao build. It observes the existing `tb.n9f.r` unified-sign call for the cart, detail, and selected already-denied APIs. It neither initiates requests nor changes arguments, return values, or exceptions. Native rewriting remains independently controlled.

Since alpha.5 each selected API is sampled at most eight times per process. The capture includes only the calling thread, at most 512 append prefixes per call, and at most 256 bytes per prefix; original lengths, sequence numbers, dropped-record counts, and total append-call counts are retained. It records each caller's offset inside the verified native library (zero means outside that library). It is not limited to the older 18-byte/0x11 heuristic. Child-thread work and bytes beyond the prefix cap are not covered.

Output field SHA-256 digests allow comparison to decoded HTTP headers without writing full output tokens. **Raw native prefixes may still contain private device or request data.** Records are written only to Taobao private cache (`alilogincompat-business-trace.jsonl`), replaced on the first write of each process. Do not publish them. Turn the switch off and restart Taobao after sampling. With rewriting, startup probe, and business trace all off, native hooks remain skipped.

Device follow-up with alpha.6: 54 command events (27 each for 70103 and 70102) were captured below the 64-event limit. Four selected business calls uniquely matched their HTTP requests and all four returned factor digests; recommendation requests succeeded while cart and IM returned 419. All four selected calls used `useWua=false`. Command 70102 received no nonempty MiniWUA string at argument 8, yet returned a MiniWUA; its 27 output digests were distinct. No Java-level 20102 call was observed through the attached bridge during this window. Internal native dispatch, cached constituent state, earlier initialization and other bridge instances remain unobserved. This identifies the actual business entry, not the server rejection rule.

Device follow-up with alpha.5: all 15 observed calls uniquely matched their captured requests, including all four security-factor digests. No valid append record was dropped by the 512-record limit; larger buffers still retain only their first 256 bytes. Cart and detail requests returned HTTP 419 while some recommendation requests succeeded. A search request was separately identified through its known test keyword in `data.params.q`: it uses the same `mtop.relationrecommend.wirelessrecommend.recommend/2.0` endpoint as other scenes. Endpoint names alone do not identify the business scene.

The verified MiniWUA decoder found identical candidate 18-byte states in successful and rejected requests in the same process. These samples do not establish the meanings of individual bits or identify the server's rejection condition. The append observations include the MiniWUA ciphertext and final token, but did not contain either decoded 7/11-byte component within any stored buffer prefix. Generation outside the calling thread/window and unrecorded buffer tails remain possible. This is diagnostic evidence, not a Taobao fix.

Local validation: C++ tests cover inactive capture, nested calls, thread isolation, copied-buffer stability, and record/prefix bounds; Android build, APK signature, and packaged JNI exports passed. Device sampling correlated seven actual calls uniquely by API and signature, with all four recorded factor digests matching captured headers. Two recommendation calls returned SUCCESS; four detail calls and one IM call returned HTTP 419. Cart/search coverage remains incomplete. These observations do not establish a server risk rule or a repair.

Offline association after collecting private data:

```sh
python3 scripts/correlate-business-trace.py --traces /private/traces.jsonl --sessions /private/sessions.json --output /private/association.json
python3 -m unittest discover -s tests -p test_business_correlation.py
```

Association requires the same API and signature digest. Repeated requests remain multiple candidates; other differing or missing factor fields are reported. These tests verify association boundaries, not a device repair.

The first five correlated MiniWUA headers also decoded to exactly the native envelope bytes captured in the same calls. Captured prefixes do not cover every append call; absence of the legacy 18-byte pattern in those prefixes does not prove absence elsewhere. Device diagnostics were disabled after sampling and the verified private sample copy was removed from the phone.


### Original VM record conversion

`scripts/expand-vm-records.py` executes the saved SG 6.8.260901 converter offline. Its shared-router output matches all 270,272 captured runtime bytes. Fourteen Taobao format `0x10003` images convert successfully; `0x10005` and other SDK fingerprints are rejected. This is record conversion, not proof of risk-handler behavior or a fix. See the [validation scope and usage](docs/taobao-vm-record-conversion.md).

### Verified offline MiniWUA container decoder

`scripts/decode-miniwua.py` implements the public container algorithm described by [byte_archaeologist](https://iosre.com/t/26281), independently checked against seven captured Android SDK 6.8.260901 business samples: CRC, component boundaries, padding, and exact re-encoding all passed. Android header constants differ from the published iOS sample. This does **not** validate the iOS bit-meaning table for Android or establish the server rejection rule.

```sh
python3 scripts/decode-miniwua.py --input /private/token.txt --key-file /private/des-material.bin --output /private/decoded.json
```

The key file must contain exactly eight raw bytes. Decoded device data goes only into the explicitly named new private file, created with mode 0600; existing files are not overwritten. Standard output contains only validation and length metadata. Do not publish decoded records. Actual-sample validation plus tampered/wrong-key/truncated-input rejection was performed locally.
