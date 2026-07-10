#!/usr/bin/env python3
"""
filecrypt_gui.py - desktop GUI for filecrypt.

Run with:  python3 filecrypt_gui.py

Screens:
  1. Create Vault  (first run only)
  2. Unlock        (every run after that - password checked against the
                     stored hash, never stored itself)
  3. Main window   (encrypt / decrypt / change password / lock)

The unlocked vault key is held only in memory for the lifetime of the app
window. Clicking "Lock" (or closing the app) discards it - it is never
written to disk.
"""

import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import filecrypt_core as core

APP_TITLE = "filecrypt"
BG = "#1e1f26"
PANEL = "#262835"
ACCENT = "#5b8cff"
ACCENT_DARK = "#4270e0"
TEXT = "#e8e9ee"
MUTED = "#9598a8"
DANGER = "#ff6b6b"
GOOD = "#4fd18b"

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 11, "bold")
FONT_TITLE = ("Segoe UI", 16, "bold")
FONT_MONO = ("Consolas", 9)


def styled_button(parent, text, command, primary=True, danger=False):
    bg = ACCENT if primary else PANEL
    if danger:
        bg = DANGER
    fg = "#ffffff" if (primary or danger) else TEXT
    b = tk.Button(
        parent, text=text, command=command, bg=bg, fg=fg,
        activebackground=ACCENT_DARK if primary else "#33364a",
        activeforeground="#ffffff", relief="flat", font=FONT_BOLD,
        padx=14, pady=8, bd=0, cursor="hand2",
    )
    return b


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.configure(bg=BG)
        self.geometry("640x520")
        self.minsize(560, 460)

        self.vault_key = None  # held only in memory, cleared on lock/close
        self.attempts_left = 3

        self.container = tk.Frame(self, bg=BG)
        self.container.pack(fill="both", expand=True)

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._route()

    def _on_close(self):
        self.vault_key = None
        self.destroy()

    def _clear(self):
        for w in self.container.winfo_children():
            w.destroy()

    def _route(self):
        self._clear()
        if not core.vault_exists():
            CreateVaultScreen(self.container, self)
        elif self.vault_key is None:
            UnlockScreen(self.container, self)
        else:
            MainScreen(self.container, self)

    def lock(self):
        self.vault_key = None
        self.attempts_left = 3
        self._route()


class Header(tk.Frame):
    def __init__(self, parent, subtitle):
        super().__init__(parent, bg=BG)
        self.pack(fill="x", pady=(36, 10), padx=40)
        tk.Label(self, text="🔒 filecrypt", font=FONT_TITLE, bg=BG, fg=TEXT).pack(anchor="w")
        tk.Label(self, text=subtitle, font=FONT, bg=BG, fg=MUTED).pack(anchor="w", pady=(4, 0))


class CreateVaultScreen(tk.Frame):
    """First-run screen: set the master password, creates ~/.filecrypt/vault.json."""

    def __init__(self, parent, app: App):
        super().__init__(parent, bg=BG)
        self.app = app
        self.pack(fill="both", expand=True)

        Header(self, "No vault found on this PC yet. Set a master password to create one.")

        form = tk.Frame(self, bg=PANEL, padx=28, pady=24)
        form.pack(fill="x", padx=40, pady=10)

        tk.Label(form, text="New master password", font=FONT_BOLD, bg=PANEL, fg=TEXT).grid(row=0, column=0, sticky="w")
        self.pw1 = tk.Entry(form, show="•", font=FONT, bg="#1a1b22", fg=TEXT, insertbackground=TEXT, relief="flat")
        self.pw1.grid(row=1, column=0, sticky="ew", pady=(4, 14), ipady=8)

        tk.Label(form, text="Confirm password", font=FONT_BOLD, bg=PANEL, fg=TEXT).grid(row=2, column=0, sticky="w")
        self.pw2 = tk.Entry(form, show="•", font=FONT, bg="#1a1b22", fg=TEXT, insertbackground=TEXT, relief="flat")
        self.pw2.grid(row=3, column=0, sticky="ew", pady=(4, 4), ipady=8)

        form.columnconfigure(0, weight=1)

        self.msg = tk.Label(self, text="", font=FONT, bg=BG, fg=DANGER)
        self.msg.pack(anchor="w", padx=40)

        tk.Label(
            self,
            text=f"Vault will be stored locally at:\n{core.VAULT_FILE}\n"
                 "Only a verification hash is saved - never the password itself.",
            font=("Segoe UI", 9), bg=BG, fg=MUTED, justify="left",
        ).pack(anchor="w", padx=40, pady=(6, 14))

        styled_button(self, "Create Vault", self._create).pack(anchor="w", padx=40)

        self.pw1.focus_set()
        self.pw2.bind("<Return>", lambda e: self._create())

    def _create(self):
        p1, p2 = self.pw1.get(), self.pw2.get()
        if len(p1) < 8:
            self.msg.config(text="Password must be at least 8 characters.")
            return
        if p1 != p2:
            self.msg.config(text="Passwords don't match.")
            return
        core.create_vault(p1)
        self.app.vault_key = core.authenticate(p1)
        self.app._route()


class UnlockScreen(tk.Frame):
    """Password entry: hashes what you type and checks it against the stored hash."""

    def __init__(self, parent, app: App):
        super().__init__(parent, bg=BG)
        self.app = app
        self.pack(fill="both", expand=True)

        Header(self, "Enter your master password to unlock.")

        form = tk.Frame(self, bg=PANEL, padx=28, pady=24)
        form.pack(fill="x", padx=40, pady=10)

        tk.Label(form, text="Master password", font=FONT_BOLD, bg=PANEL, fg=TEXT).grid(row=0, column=0, sticky="w")
        self.pw = tk.Entry(form, show="•", font=FONT, bg="#1a1b22", fg=TEXT, insertbackground=TEXT, relief="flat")
        self.pw.grid(row=1, column=0, sticky="ew", pady=(4, 4), ipady=8)
        form.columnconfigure(0, weight=1)

        self.msg = tk.Label(self, text="", font=FONT, bg=BG, fg=DANGER)
        self.msg.pack(anchor="w", padx=40, pady=(4, 14))

        self.btn = styled_button(self, "Unlock", self._unlock)
        self.btn.pack(anchor="w", padx=40)

        self.pw.focus_set()
        self.pw.bind("<Return>", lambda e: self._unlock())

    def _unlock(self):
        pw = self.pw.get()
        self.btn.config(state="disabled", text="Checking...")
        self.update_idletasks()

        def work():
            try:
                key = core.authenticate(pw)
                self.after(0, lambda: self._success(key))
            except core.WrongPassword:
                self.after(0, self._fail)

        threading.Thread(target=work, daemon=True).start()

    def _success(self, key):
        self.app.vault_key = key
        self.app._route()

    def _fail(self):
        self.app.attempts_left -= 1
        if self.app.attempts_left <= 0:
            messagebox.showerror(APP_TITLE, "Too many failed attempts. Closing.")
            self.app._on_close()
            return
        self.msg.config(text=f"Incorrect password. {self.app.attempts_left} attempt(s) left.")
        self.btn.config(state="normal", text="Unlock")
        self.pw.delete(0, "end")
        self.pw.focus_set()


class MainScreen(tk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, bg=BG)
        self.app = app
        self.pack(fill="both", expand=True)

        top = tk.Frame(self, bg=BG)
        top.pack(fill="x", padx=40, pady=(30, 6))
        tk.Label(top, text="🔓 filecrypt", font=FONT_TITLE, bg=BG, fg=TEXT).pack(side="left")
        styled_button(top, "Lock", self.app.lock, primary=False).pack(side="right")

        actions = tk.Frame(self, bg=BG)
        actions.pack(fill="x", padx=40, pady=(14, 6))
        styled_button(actions, "🔐  Encrypt file(s)...", self._encrypt).pack(side="left", padx=(0, 10))
        styled_button(actions, "🔓  Decrypt file(s)...", self._decrypt, primary=False).pack(side="left", padx=(0, 10))
        styled_button(actions, "Change password...", self._change_password, primary=False).pack(side="left")

        self.delete_original = tk.BooleanVar(value=False)
        tk.Checkbutton(
            self, text="Delete original file after operation", variable=self.delete_original,
            bg=BG, fg=MUTED, selectcolor="#1a1b22", activebackground=BG, activeforeground=TEXT,
            font=("Segoe UI", 9),
        ).pack(anchor="w", padx=40, pady=(4, 10))

        log_frame = tk.Frame(self, bg=PANEL)
        log_frame.pack(fill="both", expand=True, padx=40, pady=(0, 30))
        tk.Label(log_frame, text="Activity", font=FONT_BOLD, bg=PANEL, fg=TEXT).pack(anchor="w", padx=14, pady=(10, 0))

        self.log = tk.Text(
            log_frame, bg="#1a1b22", fg=TEXT, font=FONT_MONO, relief="flat",
            wrap="word", height=12, insertbackground=TEXT,
        )
        self.log.pack(fill="both", expand=True, padx=14, pady=10)
        self.log.tag_config("ok", foreground=GOOD)
        self.log.tag_config("err", foreground=DANGER)
        self.log.tag_config("info", foreground=MUTED)
        self.log.config(state="disabled")

        self._append(f"Vault unlocked. Working with vault at {core.VAULT_FILE}", "info")

    def _append(self, text, tag="info"):
        self.log.config(state="normal")
        self.log.insert("end", text + "\n", tag)
        self.log.see("end")
        self.log.config(state="disabled")

    def _run_bg(self, fn):
        threading.Thread(target=fn, daemon=True).start()

    def _encrypt(self):
        paths = filedialog.askopenfilenames(title="Choose file(s) to encrypt")
        if not paths:
            return
        delete_original = self.delete_original.get()
        key = self.app.vault_key

        def work():
            for p in paths:
                src = Path(p)
                try:
                    dest = core.encrypt_file(key, src, delete_original=delete_original)
                    self.after(0, lambda d=dest: self._append(f"Encrypted -> {d}", "ok"))
                except Exception as e:
                    self.after(0, lambda err=e, s=src: self._append(f"Failed to encrypt {s.name}: {err}", "err"))

        self._run_bg(work)

    def _decrypt(self):
        paths = filedialog.askopenfilenames(
            title="Choose .enc file(s) to decrypt",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
        )
        if not paths:
            return
        delete_original = self.delete_original.get()
        key = self.app.vault_key

        def work():
            for p in paths:
                src = Path(p)
                try:
                    dest = core.decrypt_file(key, src, delete_original=delete_original)
                    self.after(0, lambda d=dest: self._append(f"Decrypted -> {d}", "ok"))
                except core.WrongPassword:
                    self.after(0, lambda s=src: self._append(
                        f"Failed to decrypt {s.name}: wrong vault key for this file.", "err"))
                except core.FilecryptError as e:
                    self.after(0, lambda err=e, s=src: self._append(f"Failed to decrypt {s.name}: {err}", "err"))

        self._run_bg(work)

    def _change_password(self):
        ChangePasswordDialog(self.app, self)


class ChangePasswordDialog(tk.Toplevel):
    def __init__(self, app: App, main_screen: MainScreen):
        super().__init__(app)
        self.app = app
        self.main_screen = main_screen
        self.title("Change master password")
        self.configure(bg=BG)
        self.geometry("420x360")
        self.resizable(False, False)
        self.transient(app)
        self.grab_set()

        self.rewrap_files = []

        pad = {"padx": 24}
        tk.Label(self, text="Change master password", font=FONT_BOLD, bg=BG, fg=TEXT).pack(anchor="w", pady=(20, 10), **pad)

        tk.Label(self, text="Current password", bg=BG, fg=TEXT, font=FONT).pack(anchor="w", **pad)
        self.cur = tk.Entry(self, show="•", bg="#1a1b22", fg=TEXT, insertbackground=TEXT, relief="flat", font=FONT)
        self.cur.pack(fill="x", pady=(2, 10), ipady=6, **pad)

        tk.Label(self, text="New password", bg=BG, fg=TEXT, font=FONT).pack(anchor="w", **pad)
        self.new1 = tk.Entry(self, show="•", bg="#1a1b22", fg=TEXT, insertbackground=TEXT, relief="flat", font=FONT)
        self.new1.pack(fill="x", pady=(2, 10), ipady=6, **pad)

        tk.Label(self, text="Confirm new password", bg=BG, fg=TEXT, font=FONT).pack(anchor="w", **pad)
        self.new2 = tk.Entry(self, show="•", bg="#1a1b22", fg=TEXT, insertbackground=TEXT, relief="flat", font=FONT)
        self.new2.pack(fill="x", pady=(2, 6), ipady=6, **pad)

        self.rewrap_label = tk.Label(self, text="0 file(s) selected to re-key", bg=BG, fg=MUTED, font=("Segoe UI", 9))
        self.rewrap_label.pack(anchor="w", **pad)
        styled_button(self, "Select .enc files to re-key (optional)...", self._pick_files, primary=False).pack(
            anchor="w", pady=(6, 14), **pad)

        self.msg = tk.Label(self, text="", bg=BG, fg=DANGER, font=FONT)
        self.msg.pack(anchor="w", **pad)

        styled_button(self, "Update password", self._submit).pack(anchor="w", **pad)

    def _pick_files(self):
        paths = filedialog.askopenfilenames(
            title="Select .enc files to re-key under the new password",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
        )
        if paths:
            self.rewrap_files = list(paths)
            self.rewrap_label.config(text=f"{len(paths)} file(s) selected to re-key")

    def _submit(self):
        cur, n1, n2 = self.cur.get(), self.new1.get(), self.new2.get()
        if len(n1) < 8:
            self.msg.config(text="New password must be at least 8 characters.")
            return
        if n1 != n2:
            self.msg.config(text="New passwords don't match.")
            return
        try:
            core.rotate_password(cur, n1, rewrap_files=self.rewrap_files)
        except core.WrongPassword:
            self.msg.config(text="Current password is incorrect.")
            return
        self.app.vault_key = core.authenticate(n1)
        self.main_screen._append("Master password changed.", "ok")
        if self.rewrap_files:
            self.main_screen._append(f"Re-keyed {len(self.rewrap_files)} file(s).", "ok")
        self.destroy()


if __name__ == "__main__":
    App().mainloop()
