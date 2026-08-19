import os
import sys
import tkinter as tk
from tkinter import messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from canaryguard.config import Config
from canaryguard.embedtokens import EmbedTokenManager


def _log(msg):
    print(f"[honeytoken-builder] {msg}")


class HoneytokenBuilderApp:
    def __init__(self, root):
        self.root = root
        root.title("CanaryGuard - Honeytoken Builder")
        root.geometry("620x520")
        root.configure(bg="#0f1115")

        try:
            self.config = Config.load()
        except Exception as exc:
            messagebox.showerror("Config error", str(exc))
            root.destroy()
            return
        self.mgr = EmbedTokenManager(self.config)
        self._build_ui()

    def _build_ui(self):
        f = self.root
        style = {"bg": "#0f1115", "fg": "#e6e9ef", "font": ("Segoe UI", 10)}

        title = tk.Label(f, text="Honeytoken Builder", bg="#0f1115", fg="#4f8cff",
                         font=("Segoe UI", 16, "bold"))
        title.pack(pady=(16, 4))
        sub = tk.Label(f, text="Paste a key/token/API key -> it gets hidden inside a normal file + beacon",
                       bg="#0f1115", fg="#8b93a3", font=("Segoe UI", 9))
        sub.pack()

        # secret input
        lbl = tk.Label(f, text="Secret (key / token / API key):", **style)
        lbl.pack(anchor="w", padx=24, pady=(14, 4))
        self.secret_var = tk.StringVar()
        self.secret_entry = tk.Entry(f, textvariable=self.secret_var, width=72, bg="#1c212b",
                                     fg="#e6e9ef", insertbackground="#e6e9ef", relief="flat")
        self.secret_entry.pack(padx=24, ipady=5)

        # filename
        lbl2 = tk.Label(f, text="Output filename:", **style)
        lbl2.pack(anchor="w", padx=24, pady=(10, 4))
        self.name_var = tk.StringVar(value="credentials.txt")
        self.name_entry = tk.Entry(f, textvariable=self.name_var, width=72, bg="#1c212b",
                                   fg="#e6e9ef", insertbackground="#e6e9ef", relief="flat")
        self.name_entry.pack(padx=24, ipady=5)

        # type radio
        lbl3 = tk.Label(f, text="File type (how the secret is hidden):", **style)
        lbl3.pack(anchor="w", padx=24, pady=(10, 4))
        self.kind_var = tk.StringVar(value="txt")
        row = tk.Frame(f, bg="#0f1115")
        row.pack(anchor="w", padx=24)
        for val, txt, desc in [
            ("txt", "TXT", "zero-width chars (invisible line)"),
            ("pdf", "PDF", "hidden stream + metadata"),
            ("image", "PNG image", "LSB steganography in pixels"),
        ]:
            tk.Radiobutton(row, text=txt, variable=self.kind_var, value=val,
                           bg="#0f1115", fg="#e6e9ef", selectcolor="#1c2637",
                           activebackground="#0f1115", activeforeground="#4f8cff").pack(side="left", padx=6)
            tk.Label(row, text=desc, bg="#0f1115", fg="#8b93a3",
                     font=("Segoe UI", 8)).pack(side="left", padx=(0, 14))

        # folder
        lbl4 = tk.Label(f, text="Output folder:", **style)
        lbl4.pack(anchor="w", padx=24, pady=(10, 4))
        frow = tk.Frame(f, bg="#0f1115")
        frow.pack(anchor="w", padx=24, fill="x")
        self.folder_var = tk.StringVar(value=self.mgr.folder)
        self.folder_entry = tk.Entry(frow, textvariable=self.folder_var, bg="#1c212b",
                                     fg="#e6e9ef", insertbackground="#e6e9ef", relief="flat")
        self.folder_entry.pack(side="left", fill="x", expand=True, ipady=5)
        tk.Button(frow, text="Browse", command=self._browse, bg="#1c2637", fg="#4f8cff",
                  relief="flat", activebackground="#22304a", activeforeground="#4f8cff").pack(side="left", padx=6)

        # generate button
        self.gen_btn = tk.Button(f, text="Create embedded file + register beacon", command=self._generate,
                                 bg="#1c2637", fg="#2ecc71", font=("Segoe UI", 11, "bold"), relief="flat",
                                 activebackground="#22304a", activeforeground="#2ecc71")
        self.gen_btn.pack(pady=(16, 6), ipadx=10, ipady=6)

        # result box
        self.result = tk.Text(f, height=9, width=70, bg="#0b0e12", fg="#93c5fd",
                              relief="flat", font=("Consolas", 9))
        self.result.pack(padx=24, pady=(4, 12), fill="both", expand=True)

    def _browse(self):
        from tkinter import filedialog
        folder = filedialog.askdirectory(initialdir=self.mgr.folder)
        if folder:
            self.folder_var.set(folder)

    def _generate(self):
        secret = self.secret_var.get().strip()
        name = self.name_var.get().strip()
        kind = self.kind_var.get()
        folder = self.folder_var.get().strip()
        if not secret:
            messagebox.showwarning("Missing secret", "Enter the key/token/API key first.")
            return
        if not name:
            messagebox.showwarning("Missing filename", "Enter an output filename.")
            return
        ext = {"txt": ".txt", "pdf": ".pdf", "image": ".png"}[kind]
        if not name.lower().endswith(ext):
            name = name.rsplit(".", 1)[0] if "." in name else name
            name += ext
        self.gen_btn.config(state="disabled")
        self.gen_btn.config(text="Creating...")
        try:
            old = self.mgr.folder
            self.mgr.folder = folder
            path, token_id, beacon = self.mgr.make_custom(kind, name, secret)
            self.mgr.folder = old
            self.result.delete("1.0", tk.END)
            self.result.insert(tk.END,
                f"Created:  {path}\n"
                f"Token:    {token_id}\n"
                f"Beacon:   {beacon}\n"
                f"Secret:   {secret[:40]}{'...' if len(secret) > 40 else ''}\n"
                f"Hidden:   LSB steganography / metadata / zero-width\n\n"
                f"The file looks normal. Anyone who opens it on this PC\n"
                f"or follows the beacon will fire a critical alert.")
        except Exception as exc:
            messagebox.showerror("Error", str(exc))
        finally:
            self.gen_btn.config(state="normal")
            self.gen_btn.config(text="Create embedded file + register beacon")


def main():
    root = tk.Tk()
    HoneytokenBuilderApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()