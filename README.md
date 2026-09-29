# TronclassJpush

一个通过Jpush长连接接收Tronclass签到、通知等事件的概念验证项目，用于替换轮询监测方式。本项目负责完成设备注册、保持接收连接、解析 Push 事件并输出结果；

本项目基于python重写的[jpush-go](https://github.com/thibauddavid/jpush-go)实现。
## 项目边界

- 直接使用本地 `jpush/` 包完成 JCore 注册、登录、心跳和 Push 接收。
- 通过 SIS 服务发现长连接地址，也可以手动传入服务地址。
- 认证成功后复用外部 SDK 的会话完成服务端换票，并从账号接口获取官方 alias/tags。
- 接收投递到当前设备的 Push，不在传输层过滤消息。
- 识别 `NUMBER_ROLLCALL`、`RADAR_ROLLCALL` 和 `QRCODE_ROLLCALL` 三类签到事件。

## 目录结构

```text
main.py             启动入口和参数解析
auth_adapter.py     通用外部认证 SDK 适配层
account_binding.py  认证会话换票和账号 alias/tags 获取
jpush_monitor.py    JPush 接收、Payload 解析和监测调度
event_handler.py    事件处理边界，目前只做占位输出
jpush/              内置 JPush/JCore 客户端实现
requirements.txt    运行时依赖
```

## 环境要求

- Python 3.10 或更高版本
- 外部SDK实现Tronclass登录

## 安装

PowerShell：

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```


## 配置外部认证 SDK

复制项目中的 `config.example.json` 为 `config.json`，再填写本地配置。
`config.json` 已被 `.gitignore` 忽略，不应提交具体 SDK 路径或认证参数：

```json
{
  "auth_sdk": {
    "path": "<sdk-directory>",
    "module": "<module-name>",
    "factory": "<factory-or-class-name>",
    "login_method": "<login-method>",
    "user_info_method": "<user-info-method>",
    "constructor_kwargs": {}
  }
}
```

`path` 可以是绝对路径，也可以是相对于 `config.json` 的路径。认证 SDK
需要提供登录方法和用户信息方法，并返回一个已认证且支持 `get`/`post` 的
会话对象。项目不会导入具体 SDK，也不读取 SDK 环境变量或命令行参数。

## 启动

完成认证配置后运行：

```powershell
python main.py
```

常用参数：

```text
--alias ALIAS             可选，仅用于调试时覆盖自动获取的 alias
--tag TAG                 可选，仅用于调试时覆盖自动获取的 tag；可重复传入
--store PATH              设备凭证保存路径，默认 data/jpush/credentials.json
--server HOST:PORT        手动指定 JPush 长连接地址，可重复传入
--stdin                   使用 JSON Lines 输入进行本地监听器回归测试，仍需认证配置
```

默认流程会复刻畅课的账号绑定链路：使用认证 SDK 返回的会话完成 OIDC 换票，
调用账号服务的用户标签接口，取得当前账号的 alias 和完整 tags，然后依次发送
JCore `cmd=0x1c` 标签绑定与 `cmd=0x1d` alias 绑定。抓包中的账号值不会写入仓库。

外部认证 SDK 的登录方法必须返回一个可执行 `get`/`post` 的已认证会话对象；
认证适配器只负责提供该会话，项目本身不导入或绑定具体 SDK。

## 消息处理行为

接收到 Push 后，程序会输出事件摘要并交给 `event_handler.py`：

- 已识别的签到事件输出 `[placeholder]`，不会执行实际签到。
- 其他事件输出 `[ignored]`，不会继续执行业务处理。
- 原始 Payload 在内部事件对象中保留，但当前默认处理器不会完整打印或持久化。
