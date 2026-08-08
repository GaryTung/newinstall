Ubuntu 24系统安装命令，默认登录用户 ubuntu 并不是 root；通过 sudo bash 可以直接获得安装所需权限。
```bash
curl -fsSL https://raw.githubusercontent.com/GaryTung/newinstall/main/install.sh | sudo bash
```

自定义端口安装
例如管理端口改为 18877，本机代理端口改为 17928：

```bash
curl -fsSL https://raw.githubusercontent.com/GaryTung/newinstall/main/install.sh | sudo env UI_PORT=18877 PROXY_PORT=17928 bash
```

安装后操作
安装完成后终端会显示：
管理后台地址
随机管理账号
随机管理密码
随机隐藏路径
本机代理端口

管理命令：
```bash
sudo ml status
sudo ml credentials
sudo ml restart
sudo ml logs
```

还需要在安全列表中放行管理端口，例如：
协议：TCP
目标端口：8787
来源：建议仅填写你自己的公网 IP
