# 本地SOCKS5代理池中转工具

> © 灯火通明（济宁）网络有限公司  
> 本程序仅供学习与技术交流，禁止商业用途。

## 简介

本项目是一个基于Python和PyQt5开发的本地SOCKS5代理中转工具，支持通过API动态获取SOCKS5代理池，并在本地端口监听，自动高并发轮换出口。适用于需要多出口、轮换IP、方便管理和GUI操作的场景。

## 功能特点

- 支持SOCKS5代理协议的本地监听（如127.0.0.1:1080）
- 每个连接自动随机选择API代理池的一个SOCKS5出口
- 支持高并发（线程池可调节，默认100并发）
- GUI界面，支持自定义API地址、本地端口，一键测试API和启动/停止服务
- 自动记忆上次配置，启动即恢复
- 日志输出直观，便于观察和排查问题
- 版权声明清晰，专为学习和技术交流设计

## 环境依赖

- Python 3.7 及以上
- PyQt5
- requests
- pysocks

安装依赖：
```bash
pip install PyQt5 requests pysocks
```

## 使用方法

1. 启动程序：
   ```bash
   python proxy_gui_socks5.py
   ```
2. 在界面中输入你的API接口地址（返回SOCKS5代理池的接口），例如：
   ```
   https://your-api.com/getip?num=10&type=socks5&token=xxxx
   ```
3. 设置本地监听端口（如1080），可自定义。
4. 点击“测试API”可预览API返回的代理池IP，确认API可用。
5. 点击“启动代理服务”，本地SOCKS5代理即开始监听，自动轮换出口。
6. 在你的软件或系统中设置SOCKS5代理为 `127.0.0.1:端口` 即可使用代理池。
7. 程序会自动记忆上次API和端口设置，下次启动自动填充。

## 配置文件

配置文件为 `config.json`，保存在程序同目录下。可手动编辑，内容示例：
```json
{
  "api_url": "https://your-api.com/getip?num=10&type=socks5&token=xxxx",
  "local_port": "1080"
}
```

## 日志与版权

- 程序运行日志会在界面下方实时输出，便于调试和观察出口IP分配。
- **版权归灯火通明（济宁）网络有限公司所有，仅供学习与技术交流，禁止商业用途。**

## 常见问题

- **如何测试端口监听？**  
  可用netstat、telnet、curl命令。
- **支持多少并发？**  
  默认支持100并发连接，可在源码中调节`max_workers`参数。
- **支持用户名密码代理吗？**  
  目前暂未集成，如有需求可联系开发者或自行扩展。

## 联系与支持

如需定制开发或技术支持，请联系  
灯火通明（济宁）网络有限公司

---

## License

仅供学习与技术交流，禁止商业用途。
