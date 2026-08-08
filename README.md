```bash
bash <(curl -fsSL https://raw.githubusercontent.com/你的用户名/你的仓库/main/install.sh)
```

自定义管理端口和本机代理端口：

```bash
UI_PORT=18877 PROXY_PORT=17928 bash <(curl -fsSL https://raw.githubusercontent.com/你的用户名/你的仓库/main/install.sh)
```

`install.sh` 已嵌入完整、经过校验的 AimiliVPN 安装包。运行时会先验证 SHA-256，再解压到临时目录并调用正式安装器。

程序升级后，在 Windows 工作目录重新运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\build-github-installer.ps1
```

随后将新生成的 `github-one-line/install.sh` 提交到 GitHub。
