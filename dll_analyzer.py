import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD
import struct
import os
from datetime import datetime

class DLLAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("DLL 分析工具")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f4f8')
        
        # 标题
        title_frame = tk.Frame(root, bg='#2563eb', pady=15)
        title_frame.pack(fill='x')
        
        title_label = tk.Label(title_frame, text="🔍 DLL 分析工具", 
                              font=('Microsoft YaHei UI', 18, 'bold'),
                              bg='#2563eb', fg='white')
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="拖入 DLL 文件或点击选择", 
                                 font=('Microsoft YaHei UI', 10),
                                 bg='#2563eb', fg='#e0e7ff')
        subtitle_label.pack()
        
        # 拖放区域
        drop_frame = tk.Frame(root, bg='#f0f4f8')
        drop_frame.pack(pady=20, padx=20, fill='x')
        
        self.drop_label = tk.Label(drop_frame, 
                                   text="📁 拖入 DLL 文件到此处\n\n或点击下方按钮选择文件",
                                   font=('Microsoft YaHei UI', 12),
                                   bg='white',
                                   fg='#64748b',
                                   relief='solid',
                                   borderwidth=2,
                                   padx=20,
                                   pady=40)
        self.drop_label.pack(fill='x')
        
        # 注册拖放
        self.drop_label.drop_target_register(DND_FILES)
        self.drop_label.dnd_bind('<<Drop>>', self.on_drop)
        
        # 选择文件按钮
        btn_frame = tk.Frame(root, bg='#f0f4f8')
        btn_frame.pack(pady=10)
        
        select_btn = tk.Button(btn_frame, text="选择 DLL 文件", 
                              command=self.select_file,
                              font=('Microsoft YaHei UI', 11),
                              bg='#2563eb', fg='white',
                              padx=20, pady=10,
                              relief='flat',
                              cursor='hand2')
        select_btn.pack()
        
        # 创建笔记本（标签页）
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, padx=20, fill='both', expand=True)
        
        # 基本信息标签页
        self.info_frame = tk.Frame(self.notebook, bg='white')
        self.notebook.add(self.info_frame, text="📋 基本信息")
        
        # 导出函数标签页
        self.functions_frame = tk.Frame(self.notebook, bg='white')
        self.notebook.add(self.functions_frame, text="📦 导出函数")
        
        # 节信息标签页
        self.sections_frame = tk.Frame(self.notebook, bg='white')
        self.notebook.add(self.sections_frame, text="🗂️ 节信息")
        
        # 初始化信息显示区域
        self.init_info_tab()
        self.init_functions_tab()
        self.init_sections_tab()
        
    def init_info_tab(self):
        # 创建滚动文本框
        scroll = tk.Scrollbar(self.info_frame)
        scroll.pack(side='right', fill='y')
        
        self.info_text = tk.Text(self.info_frame, 
                                font=('Consolas', 10),
                                wrap='word',
                                yscrollcommand=scroll.set,
                                padx=15, pady=15)
        self.info_text.pack(fill='both', expand=True)
        scroll.config(command=self.info_text.yview)
        
        self.info_text.insert('1.0', "等待分析 DLL 文件...")
        self.info_text.config(state='disabled')
        
    def init_functions_tab(self):
        # 搜索框
        search_frame = tk.Frame(self.functions_frame, bg='white')
        search_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(search_frame, text="🔍 搜索:", 
                font=('Microsoft YaHei UI', 10),
                bg='white').pack(side='left', padx=5)
        
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_functions)
        
        search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                               font=('Microsoft YaHei UI', 10), width=30)
        search_entry.pack(side='left', padx=5)
        
        self.func_count_label = tk.Label(search_frame, text="",
                                         font=('Microsoft YaHei UI', 10),
                                         bg='white', fg='#64748b')
        self.func_count_label.pack(side='left', padx=10)
        
        # 创建列表框
        list_frame = tk.Frame(self.functions_frame)
        list_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side='right', fill='y')
        
        self.functions_listbox = tk.Listbox(list_frame,
                                           font=('Consolas', 10),
                                           yscrollcommand=scrollbar.set,
                                           selectmode='extended')
        self.functions_listbox.pack(fill='both', expand=True)
        scrollbar.config(command=self.functions_listbox.yview)
        
        # 右键菜单
        self.context_menu = tk.Menu(self.functions_listbox, tearoff=0)
        self.context_menu.add_command(label="复制选中", command=self.copy_selected)
        self.context_menu.add_command(label="复制全部", command=self.copy_all)
        
        self.functions_listbox.bind("<Button-3>", self.show_context_menu)
        
    def init_sections_tab(self):
        # 创建树形视图
        columns = ('name', 'virtual_address', 'virtual_size', 'raw_size')
        
        self.sections_tree = ttk.Treeview(self.sections_frame, 
                                         columns=columns, 
                                         show='headings',
                                         height=15)
        
        self.sections_tree.heading('name', text='节名称')
        self.sections_tree.heading('virtual_address', text='虚拟地址')
        self.sections_tree.heading('virtual_size', text='虚拟大小')
        self.sections_tree.heading('raw_size', text='原始大小')
        
        self.sections_tree.column('name', width=150)
        self.sections_tree.column('virtual_address', width=150)
        self.sections_tree.column('virtual_size', width=150)
        self.sections_tree.column('raw_size', width=150)
        
        scrollbar = tk.Scrollbar(self.sections_frame, command=self.sections_tree.yview)
        self.sections_tree.configure(yscrollcommand=scrollbar.set)
        
        self.sections_tree.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        scrollbar.pack(side='right', fill='y', pady=10)
        
    def on_drop(self, event):
        file_path = event.data
        # 移除大括号（如果有）
        file_path = file_path.strip('{}')
        if file_path.lower().endswith('.dll'):
            self.analyze_dll(file_path)
        else:
            messagebox.showerror("错误", "请拖入 DLL 文件！")
            
    def select_file(self):
        file_path = filedialog.askopenfilename(
            title="选择 DLL 文件",
            filetypes=[("DLL 文件", "*.dll"), ("所有文件", "*.*")]
        )
        if file_path:
            self.analyze_dll(file_path)
            
    def analyze_dll(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # 检查 MZ 头
            if data[0:2] != b'MZ':
                messagebox.showerror("错误", "不是有效的 PE 文件！")
                return
            
            # 获取 PE 头位置
            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
            
            # 检查 PE 签名
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                messagebox.showerror("错误", "PE 签名无效！")
                return
            
            # 读取 COFF 头
            machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
            number_of_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
            timestamp = struct.unpack('<I', data[pe_offset+8:pe_offset+12])[0]
            size_of_optional_header = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
            
            # 判断架构
            arch_map = {
                0x014C: '32 位 (x86)',
                0x8664: '64 位 (x64)',
                0x0200: '64 位 (Itanium)',
                0xAA64: '64 位 (ARM64)'
            }
            architecture = arch_map.get(machine, f'未知 (0x{machine:04X})')
            
            is_64bit = machine == 0x8664
            
            # 读取可选头
            optional_header_offset = pe_offset + 24
            
            # 获取导出表信息
            data_directory_offset = optional_header_offset + (112 if is_64bit else 96)
            export_table_rva = struct.unpack('<I', data[data_directory_offset:data_directory_offset+4])[0]
            export_table_size = struct.unpack('<I', data[data_directory_offset+4:data_directory_offset+8])[0]
            
            # 读取节表
            section_table_offset = pe_offset + 24 + size_of_optional_header
            sections = []
            
            for i in range(number_of_sections):
                section_offset = section_table_offset + (i * 40)
                name = data[section_offset:section_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size = struct.unpack('<I', data[section_offset+8:section_offset+12])[0]
                virtual_address = struct.unpack('<I', data[section_offset+12:section_offset+16])[0]
                size_of_raw_data = struct.unpack('<I', data[section_offset+16:section_offset+20])[0]
                pointer_to_raw_data = struct.unpack('<I', data[section_offset+20:section_offset+24])[0]
                
                sections.append({
                    'name': name,
                    'virtual_size': virtual_size,
                    'virtual_address': virtual_address,
                    'size_of_raw_data': size_of_raw_data,
                    'pointer_to_raw_data': pointer_to_raw_data
                })
            
            # 解析导出函数
            exported_functions = []
            if export_table_rva > 0 and export_table_size > 0:
                # 找到导出表所在的节
                for section in sections:
                    if (export_table_rva >= section['virtual_address'] and 
                        export_table_rva < section['virtual_address'] + section['virtual_size']):
                        
                        file_offset = section['pointer_to_raw_data'] + (export_table_rva - section['virtual_address'])
                        
                        if file_offset < len(data) - 40:
                            # 读取导出目录表
                            number_of_names = struct.unpack('<I', data[file_offset+24:file_offset+28])[0]
                            address_of_names = struct.unpack('<I', data[file_offset+32:file_offset+36])[0]
                            
                            # 读取函数名称
                            for i in range(min(number_of_names, 10000)):
                                name_pointer_offset = section['pointer_to_raw_data'] + \
                                                     (address_of_names - section['virtual_address']) + (i * 4)
                                
                                if name_pointer_offset + 3 < len(data):
                                    name_rva = struct.unpack('<I', data[name_pointer_offset:name_pointer_offset+4])[0]
                                    name_file_offset = section['pointer_to_raw_data'] + \
                                                      (name_rva - section['virtual_address'])
                                    
                                    if name_file_offset < len(data):
                                        # 读取以 null 结尾的字符串
                                        end = data.find(b'\x00', name_file_offset)
                                        if end != -1:
                                            func_name = data[name_file_offset:end].decode('ascii', errors='ignore')
                                            if func_name and len(func_name) < 200:
                                                exported_functions.append(func_name)
                        break
            
            # 显示基本信息
            self.display_info(file_path, data, architecture, timestamp, 
                            number_of_sections, export_table_rva, 
                            export_table_size, len(exported_functions))
            
            # 显示导出函数
            self.display_functions(exported_functions)
            
            # 显示节信息
            self.display_sections(sections)
            
            # 更新拖放区域提示
            self.drop_label.config(text=f"✅ 已加载: {os.path.basename(file_path)}\n\n拖入新文件重新分析")
            
        except Exception as e:
            messagebox.showerror("错误", f"分析失败：{str(e)}")
            
    def display_info(self, file_path, data, architecture, timestamp, 
                    sections_count, export_rva, export_size, func_count):
        self.info_text.config(state='normal')
        self.info_text.delete('1.0', 'end')
        
        file_size = len(data)
        date_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        info = f"""
╔══════════════════════════════════════════════════════════════╗
║                        DLL 文件信息                          ║
╚══════════════════════════════════════════════════════════════╝

📁 文件信息
  ├─ 文件名: {os.path.basename(file_path)}
  ├─ 完整路径: {file_path}
  └─ 文件大小: {file_size:,} 字节 ({file_size/1024:.2f} KB)

🖥️ PE 信息
  ├─ 架构: {architecture}
  ├─ 编译时间: {date_str}
  └─ 节数量: {sections_count}

📦 导出信息
  ├─ 导出表 RVA: 0x{export_rva:08X}
  ├─ 导出表大小: {export_size} 字节
  └─ 导出函数数量: {func_count}

═══════════════════════════════════════════════════════════════
        """
        
        self.info_text.insert('1.0', info)
        self.info_text.config(state='disabled')
        
    def display_functions(self, functions):
        self.all_functions = functions  # 保存所有函数用于搜索
        self.functions_listbox.delete(0, 'end')
        
        if functions:
            for func in sorted(functions):
                self.functions_listbox.insert('end', func)
            self.func_count_label.config(text=f"共 {len(functions)} 个函数")
        else:
            self.functions_listbox.insert('end', "未找到导出函数")
            self.func_count_label.config(text="")
            
    def display_sections(self, sections):
        # 清空树形视图
        for item in self.sections_tree.get_children():
            self.sections_tree.delete(item)
        
        # 添加节信息
        for section in sections:
            self.sections_tree.insert('', 'end', values=(
                section['name'],
                f"0x{section['virtual_address']:08X}",
                f"{section['virtual_size']:,} 字节",
                f"{section['size_of_raw_data']:,} 字节"
            ))
            
    def filter_functions(self, *args):
        search_text = self.search_var.get().lower()
        self.functions_listbox.delete(0, 'end')
        
        if hasattr(self, 'all_functions'):
            filtered = [f for f in self.all_functions if search_text in f.lower()]
            for func in sorted(filtered):
                self.functions_listbox.insert('end', func)
            self.func_count_label.config(text=f"显示 {len(filtered)}/{len(self.all_functions)} 个函数")
            
    def show_context_menu(self, event):
        self.context_menu.post(event.x_root, event.y_root)
        
    def copy_selected(self):
        selected = self.functions_listbox.curselection()
        if selected:
            text = '\n'.join([self.functions_listbox.get(i) for i in selected])
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("成功", f"已复制 {len(selected)} 个函数名")
            
    def copy_all(self):
        if hasattr(self, 'all_functions'):
            text = '\n'.join(sorted(self.all_functions))
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("成功", f"已复制全部 {len(self.all_functions)} 个函数名")

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = DLLAnalyzer(root)
    root.mainloop()