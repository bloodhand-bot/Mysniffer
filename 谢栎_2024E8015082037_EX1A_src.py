import tkinter as tk
from tkinter import ttk, Label, Frame, END, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, IPv6, Raw
import threading
import time
import socket
import re

# 定义全局变量
filter_expression = None
running = threading.Event()
packets = []  # 存储所有捕获的数据包
sniffing_thread = None
MAX_PACKETS = 600  # 最大记录的数据包数量
SNIFF_TIMEOUT = 60  # 设置嗅探超时时间为 60 秒

# 定义协议号到协议名称的映射表
protocol_map = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    2: "IGMP",
    47: "GRE",
    89: "OSPF",
}

# 定义一个函数来获取协议名称
def get_protocol_name(proto_num):
    return protocol_map.get(proto_num, f"Unknown-{proto_num}")

# 定义一个函数来处理捕获的数据包
def packet_callback(packet):
    global packets
    if not running.is_set():  # 检查是否已经停止嗅探
        return

    if len(packets) < MAX_PACKETS:
        packets.append(packet)
        packet_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = get_protocol_name(packet[IP].proto)
        elif IPv6 in packet:
            src = packet[IPv6].src
            dst = packet[IPv6].dst
            proto = get_protocol_name(packet[IPv6].nh)
        elif ARP in packet:  # 处理 ARP 数据包
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
            proto = "ARP"
        elif TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80 or 
                               packet[TCP].dport == 443 or packet[TCP].sport == 443):
            proto = "HTTP"
        else:
            src = "未知"
            dst = "未知"
            proto = "未知"
        info = packet.summary()
        tree.insert('', END, values=(len(packets), packet_time, src, dst, proto, info))
        print(f"捕获到数据包：{src} -> {dst}, 协议：{proto}")

# 定义一个函数，将 BPF 表达式转换为 Python 过滤函数
def build_lfilter(filter_exp):
    filter_exp = filter_exp.lower().strip()
    protocol_map = {
        'tcp': 'TCP in packet',
        'udp': 'UDP in packet',
        'icmp': 'ICMP in packet',
        'ip': 'IP in packet',
        'ipv6': 'IPv6 in packet',
        'arp': 'ARP in packet',
        'http': "TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80 or " \
                "packet[TCP].dport == 443 or packet[TCP].sport == 443)"  # 添加HTTP协议
    }

    for bpf_proto, py_expr in protocol_map.items():
        filter_exp = re.sub(r'\b{}\b'.format(bpf_proto), py_expr, filter_exp)

    def replace_host(match):
        direction = match.group(1)
        host = match.group(2)
        try:
            ip_addrs = socket.gethostbyname_ex(host)[2]
            if not ip_addrs:
                raise socket.gaierror("No IP addresses found")
            ip_expr = " or ".join(
                f"IP in packet and packet[IP].{direction} == '{ip}'" for ip in ip_addrs if is_ipv4(ip)
            )
            if not ip_expr:
                ip_expr = "IPv6 in packet and packet[IPv6].{0} == '{1}'".format(direction, ip_addrs[0])
            return f"({ip_expr})"
        except socket.gaierror as e:
            messagebox.showerror("错误", f"无法解析主机名：{host}\n{e}")
            return "False"

    filter_exp = re.sub(r'(src|dst) host (\S+)', replace_host, filter_exp)

    filter_exp = filter_exp.replace(' and ', ' and ').replace(' or ', ' or ').replace('not ', 'not ')

    print(f"构建的过滤表达式：{filter_exp}")

    def lfilter(packet):
        try:
            return eval(filter_exp)
        except Exception as e:
            print(f"过滤表达式错误：{e}")
            running.clear()  # 停止嗅探
            start_button.config(state=tk.NORMAL)
            stop_button.config(state=tk.DISABLED)
            return False

    return lfilter

def is_ipv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        return False

# 定义一个函数来启动嗅探器
def start_sniffing():
    global filter_expression, running, sniffing_thread, packets
    filter_expression = filter_entry.get().strip()

    if not filter_expression:
        messagebox.showerror("错误", "过滤表达式不能为空。")
        return

    clear_captures()
    packets = []

    try:
        lfilter_func = build_lfilter(filter_expression)
    except Exception as e:
        messagebox.showerror("错误", f"无效的过滤表达式：\n{e}")
        return

    running.set()  # 设置事件为 True

    def sniff_packets():
        try:
            sniff(
                prn=packet_callback,
                store=0,
                lfilter=lfilter_func,
                stop_filter=lambda x: not running.is_set(),
                timeout=SNIFF_TIMEOUT  # 设置超时时间
            )
        except Exception as e:
            messagebox.showerror("错误", f"嗅探器遇到错误：\n{e}")
        finally:
            running.clear()
            start_button.config(state=tk.NORMAL)
            stop_button.config(state=tk.DISABLED)

    sniffing_thread = threading.Thread(target=sniff_packets)
    sniffing_thread.start()
    start_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

# 定义一个函数来停止嗅探器
def stop_sniffing():
    global running, sniffing_thread
    running.clear()  # 设置事件为 False
    if sniffing_thread is not None:
        sniffing_thread.join(timeout=1.0)  # 等待嗅探线程结束，超时时间为1秒
        if sniffing_thread.is_alive():
            messagebox.showwarning("警告", "嗅探线程未能及时结束，已被强制终止。")
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

# 定义一个函数来清除捕获的数据包
def clear_captures():
    global packets
    for i in tree.get_children():
        tree.delete(i)
    packets.clear()
    details_tree.delete(*details_tree.get_children())

# 定义一个函数来显示选中数据包的详细信息
def show_selected_packet_details():
    selected_item = tree.selection()
    if selected_item:
        index = int(tree.item(selected_item)['values'][0]) - 1
        if index < 0 or index >= len(packets):
            messagebox.showerror("错误", "选中的数据包索引无效。")
            return
        packet = packets[index]  # 获取选中的数据包
        # 清空之前的内容
        details_tree.delete(*details_tree.get_children())
        # 解析数据包的各层
        layers = []
        current_layer = packet
        while current_layer:
            layers.append(current_layer)
            current_layer = current_layer.payload if hasattr(current_layer, 'payload') else None

        for layer in layers:
            layer_name = layer.name
            parent = ""
            try:
                parent = details_tree.insert('', END, text=layer_name, open=False)
            except Exception as e:
                print(f"插入层 {layer_name} 失败：{e}")
                continue
            # 添加层的字段
            for field_name, field_value in layer.fields.items():
                details_tree.insert(parent, END, text=field_name, values=(field_value,))

# 定义一个函数来退出应用程序
def exit_application():
    if running.is_set():
        stop_sniffing()
    root.destroy()

# 创建主窗口
root = tk.Tk()
root.title("网络嗅探器")

# 创建顶部框架用于放置数据包列表
top_frame = Frame(root)
top_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

# 创建表格来显示数据包信息
tree =ttk.Treeview(top_frame, columns=('No.', 'Time', 'Source', 'Destination', 'Protocol', 'Info'), show='headings')
tree.heading('No.', text='包序号')
tree.heading('Time', text='时间')
tree.heading('Source', text='源地址')
tree.heading('Destination', text='目的地址')
tree.heading('Protocol', text='协议')
tree.heading('Info', text='信息')
tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

#添加滚动条
scrollbar = ttk.Scrollbar(top_frame, orient='vertical', command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

##创建过滤表达式框架
filter_frame = Frame(root)
filter_frame.pack(side=tk.TOP, fill=tk.X)

#创建过滤表达式输入框
filter_label = Label(filter_frame, text="过滤表达式:")
filter_label.pack(side=tk.LEFT, padx=5, pady=5)
filter_entry = tk.Entry(filter_frame)
filter_entry.pack(side=tk.LEFT, fill=tk.X, padx=10, pady=5, expand=True)

#创建底部框架用于放置按钮
bottom_frame = Frame(root)
bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

#创建右侧框架
right_frame = Frame(root)
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

#创建详细信息的 Treeview
details_tree_frame = Frame(right_frame)
details_tree_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

columns = ('Value',)
details_tree = ttk.Treeview(details_tree_frame, columns=columns, show='tree headings')
details_tree.heading('#0', text='字段')
details_tree.heading('Value', text='值')
details_tree.column('Value', width=300)
details_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

#添加滚动条
details_scrollbar = ttk.Scrollbar(details_tree_frame, orient='vertical', command=details_tree.yview)
details_tree.configure(yscrollcommand=details_scrollbar.set)
details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

#创建按钮来启动和停止嗅探器
start_button = tk.Button(bottom_frame, text="开始嗅探", command=start_sniffing)
start_button.pack(side=tk.LEFT, padx=5, pady=5)
stop_button = tk.Button(bottom_frame, text="停止嗅探", command=stop_sniffing, state=tk.DISABLED)
stop_button.pack(side=tk.LEFT, padx=5, pady=5)

#创建按钮来显示选中数据包的详细信息
details_button = tk.Button(bottom_frame, text="显示详细信息", command=show_selected_packet_details)
details_button.pack(side=tk.LEFT, padx=5, pady=5)

#创建按钮来清除捕获的数据包
clear_button = tk.Button(bottom_frame, text="清除捕获", command=clear_captures)
clear_button.pack(side=tk.LEFT, padx=5, pady=5)

#创建按钮来退出应用程序
exit_button = tk.Button(bottom_frame, text="退出", command=exit_application)
exit_button.pack(side=tk.LEFT, padx=5, pady=5)

#绑定双击事件以显示详细信息
tree.bind("<Double-1>", lambda event: show_selected_packet_details())

#运行程序
root.mainloop()