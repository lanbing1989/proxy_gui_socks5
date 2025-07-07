import sys
import threading
import requests
import time
import random
import socket
import select
import socks  # PySocks
import concurrent.futures
import json
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit,
    QPushButton, QTextEdit, QHBoxLayout
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject

CONFIG_FILE = "config.json"

class Communicate(QObject):
    log = pyqtSignal(str)

class ProxyGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("本地SOCKS5代理池中转工具")
        self.resize(600, 440)
        self.stop_flag = False
        self.api_url = ""
        self.local_port = 0
        self.proxy_pool = []
        self.comm = Communicate()
        self.comm.log.connect(self.append_log)
        self.server_thread = None
        self.refresh_thread = None
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=100)
        self.init_ui()
        self.load_config()

    def init_ui(self):
        layout = QVBoxLayout()

        api_layout = QHBoxLayout()
        api_label = QLabel("API接口地址:")
        self.api_edit = QLineEdit()
        self.api_edit.setPlaceholderText("如 https://your-api.com/getip?num=10&type=socks5&token=xxxx")
        api_layout.addWidget(api_label)
        api_layout.addWidget(self.api_edit)
        layout.addLayout(api_layout)

        port_layout = QHBoxLayout()
        port_label = QLabel("本地端口:")
        self.port_edit = QLineEdit()
        self.port_edit.setText("1080")
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_edit)
        layout.addLayout(port_layout)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("启动代理服务")
        self.stop_btn = QPushButton("停止服务")
        self.test_btn = QPushButton("测试API")
        self.stop_btn.setEnabled(False)
        self.start_btn.clicked.connect(self.start_proxy)
        self.stop_btn.clicked.connect(self.stop_proxy)
        self.test_btn.clicked.connect(self.test_api)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.test_btn)
        layout.addLayout(btn_layout)

        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        layout.addWidget(QLabel("运行日志："))
        layout.addWidget(self.log_edit)

        # 版权信息
        copyright_label = QLabel(
            "© 灯火通明（济宁）网络有限公司\n"
            "本软件仅供学习与技术交流，禁止商业用途"
        )
        copyright_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(copyright_label)

        self.setLayout(layout)

    def append_log(self, msg):
        self.log_edit.append(msg)
        self.log_edit.ensureCursorVisible()

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                self.api_edit.setText(cfg.get("api_url", ""))
                self.port_edit.setText(str(cfg.get("local_port", "1080")))
                self.comm.log.emit("已加载上次保存的配置。")
            except Exception as e:
                self.comm.log.emit(f"加载配置失败: {e}")

    def save_config(self):
        cfg = {
            "api_url": self.api_edit.text().strip(),
            "local_port": self.port_edit.text().strip()
        }
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
            self.comm.log.emit("配置已保存。")
        except Exception as e:
            self.comm.log.emit(f"保存配置失败: {e}")

    def start_proxy(self):
        self.api_url = self.api_edit.text().strip()
        try:
            self.local_port = int(self.port_edit.text().strip())
        except:
            self.comm.log.emit("本地端口必须为数字。")
            return
        if not self.api_url or self.local_port <= 0:
            self.comm.log.emit("请正确填写API接口和端口。")
            return

        self.save_config()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.stop_flag = False
        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_thread.start()
        self.refresh_thread = threading.Thread(target=self.refresh_proxy_pool_loop, daemon=True)
        self.refresh_thread.start()
        self.comm.log.emit("代理服务已启动。")

    def stop_proxy(self):
        self.comm.log.emit("正在停止服务...")
        self.stop_flag = True
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.comm.log.emit("服务已停止。")

    def fetch_proxy_pool(self):
        try:
            res = requests.get(self.api_url, timeout=8)
            lines = [line.strip() for line in res.text.strip().split("\n") if line.strip()]
            return lines
        except Exception as e:
            self.comm.log.emit(f"拉取代理池失败: {e}")
            return []

    def refresh_proxy_pool_loop(self):
        while not self.stop_flag:
            lines = self.fetch_proxy_pool()
            if lines:
                self.proxy_pool = lines
                self.comm.log.emit(f"代理池已更新，共{len(lines)}个IP。")
            else:
                self.comm.log.emit("未获取到有效代理，保留上次代理池。")
            for _ in range(60):
                if self.stop_flag:
                    break
                time.sleep(1)

    def run_server(self):
        # SOCKS5协议本地监听
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server.bind(("127.0.0.1", self.local_port))
            except Exception as e:
                self.comm.log.emit(f"端口绑定失败，可能已被占用: {e}")
                return
            server.listen(128)
            self.comm.log.emit(f"监听 127.0.0.1:{self.local_port}，等待SOCKS5连接...")

            while not self.stop_flag:
                try:
                    server.settimeout(1)
                    try:
                        client, addr = server.accept()
                    except socket.timeout:
                        continue
                    self.executor.submit(self.handle_socks5_client, client, addr)
                except Exception as e:
                    self.comm.log.emit(f"服务异常: {e}")
                    break
            server.close()
        except Exception as e:
            self.comm.log.emit(f"SOCKS5监听失败: {e}")

    def handle_socks5_client(self, client, addr):
        # 只实现最基本的SOCKS5转发，不支持认证
        try:
            client.settimeout(10)
            # 握手
            data = client.recv(262)
            if not data or data[0] != 0x05:
                client.close()
                return
            # 无认证响应
            client.sendall(b"\x05\x00")

            # 请求
            data = client.recv(4)
            if len(data) < 4 or data[0] != 0x05:
                client.close()
                return
            cmd = data[1]
            if cmd != 1:  # 只支持CONNECT
                client.sendall(b"\x05\x07\x00\x01" + b"\x00"*6)
                client.close()
                return
            addr_type = data[3]
            if addr_type == 1:  # IPv4
                addr_ip = socket.inet_ntoa(client.recv(4))
                addr_port = int.from_bytes(client.recv(2), 'big')
                remote_addr = (addr_ip, addr_port)
            elif addr_type == 3:  # 域名
                domain_len = client.recv(1)[0]
                domain = client.recv(domain_len).decode()
                addr_port = int.from_bytes(client.recv(2), 'big')
                remote_addr = (domain, addr_port)
            else:
                client.sendall(b"\x05\x08\x00\x01" + b"\x00"*6)
                client.close()
                return

            # 选择一个上游SOCKS5代理
            if not self.proxy_pool:
                self.comm.log.emit("无可用上游代理，连接被拒绝。")
                client.close()
                return
            upstream_addr = random.choice(self.proxy_pool)
            proxy_host, proxy_port = upstream_addr.split(":")
            proxy_port = int(proxy_port)

            # 通过PySocks连接上游代理
            upstream = socks.socksocket()
            upstream.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
            upstream.settimeout(10)
            try:
                upstream.connect(remote_addr)
            except Exception as e:
                self.comm.log.emit(f"上游代理连接目标失败: {upstream_addr} -> {remote_addr} ({e})")
                client.sendall(b"\x05\x05\x00\x01" + b"\x00"*6)
                client.close()
                return

            # 回复客户端连接成功
            client.sendall(b"\x05\x00\x00\x01" + b"\x00"*6)
            self.comm.log.emit(f"本地客户端 {addr} -> 远程 {remote_addr} 已通过上游 {upstream_addr} 转发")
            self.forward_loop(client, upstream)
        except Exception as e:
            self.comm.log.emit(f"SOCKS5转发失败: {e}")
            try: client.close()
            except: pass

    def forward_loop(self, s1, s2):
        sockets = [s1, s2]
        while True:
            try:
                r, w, e = select.select(sockets, [], sockets, 10)
                if e: break
                for sock in r:
                    data = sock.recv(65536)
                    if not data:
                        return
                    if sock is s1:
                        s2.sendall(data)
                    else:
                        s1.sendall(data)
            except Exception:
                break
        try: s1.close()
        except: pass
        try: s2.close()
        except: pass

    def test_api(self):
        api_url = self.api_edit.text().strip()
        if not api_url:
            self.comm.log.emit("请填写API接口地址！")
            return
        self.comm.log.emit(f"开始测试API: {api_url}")
        def do_test():
            try:
                res = requests.get(api_url, timeout=8)
                text = res.text.strip()
                if text:
                    preview = "\n".join(text.splitlines()[:10])
                    self.comm.log.emit("API响应前10行:\n" + preview)
                    self.comm.log.emit("（仅显示前10行，如有更多请下拉查看）")
                else:
                    self.comm.log.emit("API无返回内容。")
            except Exception as e:
                self.comm.log.emit(f"API连接失败: {e}")
        threading.Thread(target=do_test, daemon=True).start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ProxyGUI()
    window.show()
    sys.exit(app.exec_())