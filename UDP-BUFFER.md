# HY2 接收缓冲区（.55）

新安装及 `upgrade-dashboard.sh` 完整升级默认设置：

```text
net.core.rmem_default = 4194304
net.core.rmem_max = 4194304
```

这是 4 MiB 的 socket 接收缓冲区默认值和上限，不是 DNS 缓存，也不是固定预占
4 MiB 的总内存限制。设置影响系统中新创建的接收 socket，不仅是 HY2。
原有 socket 需要代理服务重启后才能采用新默认值。

仅应用缓冲区设置，不升级后台、不修改订阅或国家线路：

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/GaryTung/newinstall/main/configure-udp-buffer.sh)" -- --restart-xray
```

该命令只会重启正在运行的 `x-ui`，连接会短暂中断；不会启动已停止的服务，
也不会恢复 VPN Gate 拉取或检测。省略 `--restart-xray` 则只设置参数，不重启服务。
已是 4 MiB 且已重启代理的机器无需重复执行。

配置保存在 `/etc/sysctl.d/90-hy2-udp-recv.conf`，重启后会由系统加载。
旧配置与旧运行值备份到 `/var/backups/aimilivpn/udp-buffer.*`。
设置失败会尝试恢复旧配置和运行值；设置成功不意味着能消除公网链路丢包。

检查：

```bash
sysctl net.core.rmem_default net.core.rmem_max
ss -uanm 'sport = :24129'
```

若 HY2 端口不同，请替换 `24129`。检查 socket 的 `rb` 和 `d` 字段，
而不要把系统启动以来的累计错误当作本轮新增丢包。
