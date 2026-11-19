# AliLoginCompat alpha.17 修复与实机验证

日期：2026-11-20（Asia/Taipei）

## 当前结果

alpha.17 已完成构建、签名校验和手机升级安装。模块中已确认的广播、日志、原生错误状态及文件回退问题得到修复；淘宝的购物车、搜索和详情尚未通过已登录状态下的业务验收。本轮观察到会话过期、官方登录选择页和官方拒绝页，服务端拒绝的具体条件仍未定位。

## 已提交的修复

| 修复 | 作用 |
| --- | --- |
| 删除拒绝页日志中的原始 httpReferer | 避免来源 URL、查询参数随日志输出。 |
| USB 钩子核对实际返回 Intent 的 action | 多 action 过滤器返回非 USB 广播时保持原对象和内容。 |
| 原生观察代码保留原 errno | 日志、采样和查询过程保持被观察函数的错误状态。 |
| proc 替代文件采用完整复制，fdopen 失败关闭 fd | 读取、写入、创建和回卷失败时回退原文件，避免截断内容及句柄泄漏。 |

代码提交：

- [62efe945：Java 广播及日志修复](https://github.com/LIghtJUNction/AliLoginCompat/commit/62efe9451d8d149257c796d6821e4c58b54ba536)
- [2570f621：原生 I/O 修复及 alpha.17 版本](https://github.com/LIghtJUNction/AliLoginCompat/commit/2570f621ac6af4f4b3d259419ce74ff1ef8f96d2)

这些修改修复客户端的可定位缺陷。当前实测没有建立它们与解除淘宝服务器拒绝之间的因果关系。

## 验证结果

- UsbCompatPolicyTest、DenyLocationPolicyTest 通过，运行时启用 Java assertions（java -ea）。
- native_query_compat_test 通过，使用 C++17、-Wall、-Wextra、-Werror。覆盖错误码保留、接收缓冲区完整性、EISDIR、EMFILE、ENOSPC、ESPIPE、4 MiB 限制及 fdopen 失败释放。
- Android Release 构建通过；7 个打包后的 JNI 导出通过校验；APK v3 签名校验通过。
- ADB 升级安装成功；手机读回 versionCode=20、versionName=0.2.0-alpha.17。

产物：AliLoginCompat-0.2.0-alpha.17-arm64.apk

SHA-256：

```text
15374433e7e399e5589b3850a0923f789967277b2f49952e27296401545dccb8
```

## 实机证据及边界

设备运行 Android 16，淘宝版本为 10.69.0。测试在原手机的独立显示会话中进行，沿用已安装应用的数据。采样时临时开启 trace_status、保留官方拒绝页，淘宝的原生改写及环境实验保持关闭。

| 观察对象 | 本轮实际结果 | 支持的结论 |
| --- | --- | --- |
| mtop.taobao.wireless.home.newface.awesome.newget | HTTP 200 / SUCCESS | 该次首页请求成功，首页可呈现内容。 |
| mtop.taobao.wireless.amp2.im.pushnum.set | HTTP 200 / FAIL_SYS_SESSION_EXPIRED | 该响应明确报告会话过期。 |
| mtop.alibaba.havana.login.prelogininfo | HTTP 200 / SUCCESS | 预登录接口可达，登录准备请求成功。 |
| 退出未完成的登录流程 | token.get 及部分 IM 同步记录 HTTP 0 / ANDROID_SYS_LOGIN_CANCEL | 应用产生本地登录取消结果；HTTP 0 不作为服务器 HTTP 响应。 |
| 本机号码登录尝试、重新打开购物车 | 仍进入官方登录选择页，未取得已认证购物车成功响应 | 登录及购物车尚待完成验收。 |
| 关闭登录页及后续冷启动 | 出现官方“访问被拒绝”页面 | 当前访问问题仍然存在。 |

首页和预登录成功不能替代购物车、搜索、详情的成功样本。历史 HTTP 419 对照见 [启动隔离记录](taobao-startup-isolation-2026-11-17.md)；本轮不把历史状态码记作新响应。

## 收尾与下一步

临时状态观察已关闭，模块逻辑偏好已恢复原值，包括拒绝页收起开关、原关闭状态版本标记及闲鱼改写选项。淘宝进程已在关闭诊断后重新启动。

标准调试工具曾因 /data/local/tmp 及其 dalvik-cache 目录的错误 SELinux 标签无法使用。经 restorecon 只读预览核对系统预期标签后，两处目录恢复为 shell_data_file，标准 ADB 调试恢复可用。

下一项必要验证是由账号持有人通过淘宝官方手机号或支付宝流程完成现有账号认证，然后重新验证同一购物车接口、搜索结果和商品详情。若官方认证仍被拒绝，需保留官方错误信息供账号侧核查。公开记录只包含版本、代码修改、规范化 API 名和状态码，不包含账号标识、二维码、请求签名、Cookie 或令牌。
