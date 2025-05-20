# gui_demo.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from encryption_platform import EncryptionPlatform

class CryptoGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("公钥加密算法实验平台")
        self.geometry("700x600")
        self.platform = EncryptionPlatform()
        self.pub_key = None
        self.priv_key = None
        self.last_ciphertext = None

        self._build_widgets()

    def _build_widgets(self):
        # 算法选择
        ttk.Label(self, text="选择算法：").pack(anchor="w", padx=10, pady=(10, 0))
        self.algo_var = tk.StringVar(value="RSA")
        ttk.Combobox(self, textvariable=self.algo_var, values=["RSA","ElGamal","ECC"], state="readonly").pack(fill="x", padx=10)

        # 生成密钥按钮
        ttk.Button(self, text="生成密钥", command=self.generate_keys).pack(padx=10, pady=10)

        # 公钥/私钥展示
        ttk.Label(self, text="公钥：").pack(anchor="w", padx=10)
        self.pub_text = scrolledtext.ScrolledText(self, height=4)
        self.pub_text.pack(fill="x", padx=10)
        ttk.Label(self, text="私钥：").pack(anchor="w", padx=10)
        self.priv_text = scrolledtext.ScrolledText(self, height=4)
        self.priv_text.pack(fill="x", padx=10)

        # 明文输入 & 加密
        ttk.Label(self, text="输入明文：").pack(anchor="w", padx=10, pady=(10,0))
        self.plain_entry = ttk.Entry(self)
        self.plain_entry.pack(fill="x", padx=10)
        ttk.Button(self, text="加密", command=self.encrypt).pack(padx=10, pady=5)
        ttk.Label(self, text="密文：").pack(anchor="w", padx=10)
        self.cipher_text = scrolledtext.ScrolledText(self, height=4)
        self.cipher_text.pack(fill="x", padx=10)

        # 密文输入 & 解密
        ttk.Label(self, text="输入密文（留空则用上次结果）：").pack(anchor="w", padx=10, pady=(10,0))
        self.cipher_entry = ttk.Entry(self)
        self.cipher_entry.pack(fill="x", padx=10)
        ttk.Button(self, text="解密", command=self.decrypt).pack(padx=10, pady=5)
        ttk.Label(self, text="解密明文：").pack(anchor="w", padx=10)
        self.result_text = scrolledtext.ScrolledText(self, height=4)
        self.result_text.pack(fill="x", padx=10)

        # 退出按钮
        ttk.Button(self, text="退出", command=self.destroy).pack(pady=20)

    def generate_keys(self):
        algo = self.algo_var.get()
        pub, priv = self.platform.generate_keys(algo)
        self.pub_key, self.priv_key = pub, priv
        self.pub_text.delete("1.0", tk.END)
        self.priv_text.delete("1.0", tk.END)
        self.pub_text.insert(tk.END, repr(pub))
        self.priv_text.insert(tk.END, repr(priv))
        messagebox.showinfo("成功", f"{algo} 密钥对生成完成！")

    def encrypt(self):
        if not self.pub_key:
            messagebox.showwarning("错误", "请先生成密钥！")
            return
        algo = self.algo_var.get()
        msg = self.plain_entry.get().strip()
        if algo in ["RSA", "ElGamal"]:
            try:
                msg = int(msg)
            except:
                messagebox.showerror("错误", "RSA/ElGamal 明文必须为整数！")
                return

        # 调用不同算法
        if algo == "ElGamal":
            c1, c2 = self.platform.encrypt(algo, msg, self.pub_key)
            # 格式化成 (c1,c2)
            ct_str = f"({c1},{c2})"
        else:
            ct = self.platform.encrypt(algo, msg, self.pub_key)
            ct_str = str(ct)

        self.last_ciphertext = ct_str
        self.cipher_text.delete("1.0", tk.END)
        self.cipher_text.insert(tk.END, ct_str)
        messagebox.showinfo("加密", "加密成功！")

    def decrypt(self):
        if not self.priv_key:
            messagebox.showwarning("错误", "请先生成密钥！")
            return
        algo = self.algo_var.get()
        inp = self.cipher_entry.get().strip()
        # 1) 确保 ciphertext 始终是字符串
        ct_str = inp if inp else (self.last_ciphertext or "")
        if not ct_str:
            messagebox.showwarning("错误", "没有可解密的密文！")
            return

        try:
            if algo == "RSA":
                # RSA 解密需要整数
                pt = self.platform.decrypt(algo, int(ct_str), self.priv_key)
            elif algo == "ElGamal":
                    # 1. 去掉可能存在的左右括号
                    clean = ct_str.strip()
                    if clean.startswith("(") and clean.endswith(")"):
                        clean = clean[1:-1]
                    # 2. 检查逗号
                    if "," not in clean:
                        raise ValueError("ElGamal 密文格式错误，应为“(c1,c2)”或“c1,c2”")
                    # 3. 拆分并转为整数
                    a_str, b_str = clean.split(",", 1)
                    c1, c2 = int(a_str.strip()), int(b_str.strip())
                    # 4. 调用解密
                    pt = self.platform.decrypt(algo, (c1, c2), self.priv_key, self.pub_key)
            else:  # ECC
                pt = self.platform.decrypt(algo, ct_str, self.priv_key)

            # 显示结果
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, str(pt))
            messagebox.showinfo("解密", "解密成功！")
        except Exception as e:
            messagebox.showerror("解密失败", str(e))


if __name__ == "__main__":
        app = CryptoGUI()
        app.mainloop()
