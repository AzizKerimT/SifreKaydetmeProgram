import customtkinter as ctk
import sqlite3
from tkinter import messagebox

# Giriş şifresi
APP_PASSWORD = "123"

# Veritabanı başlangıcı
def init_db():
    conn = sqlite3.connect("passwords.db")
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

# Şifre ekle
def add_password(site, username, password):
    conn = sqlite3.connect("passwords.db")
    c = conn.cursor()
    c.execute("INSERT INTO passwords (site, username, password) VALUES (?, ?, ?)",
              (site, username, password))
    conn.commit()
    conn.close()

# Şifreleri al
def get_passwords(filter_text=None):
    conn = sqlite3.connect("passwords.db")
    c = conn.cursor()
    if filter_text:
        c.execute("SELECT * FROM passwords WHERE site LIKE ?", ('%' + filter_text + '%',))
    else:
        c.execute("SELECT * FROM passwords")
    results = c.fetchall()
    conn.close()
    return results

# Şifre sil
def delete_password(id_):
    conn = sqlite3.connect("passwords.db")
    c = conn.cursor()
    c.execute("DELETE FROM passwords WHERE id = ?", (id_,))
    conn.commit()
    conn.close()

# Giriş ekranı
class LoginScreen(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title("🔐 Şifre Yöneticisi - Giriş")
        self.geometry("400x300")

        self.title_label = ctk.CTkLabel(self, text="Şifre Yöneticisi", font=("Arial", 28, "bold"))
        self.title_label.pack(pady=20)

        self.password_entry = ctk.CTkEntry(self, placeholder_text="Giriş Şifresi", show="*")
        self.password_entry.pack(pady=10, padx=20)

        self.login_button = ctk.CTkButton(self, text="Giriş Yap", command=self.check_password, width=200)
        self.login_button.pack(pady=20)

    def check_password(self):
        if self.password_entry.get() == APP_PASSWORD:
            self.destroy()
            app = PasswordManager()
            app.mainloop()
        else:
            messagebox.showerror("Hata", "Yanlış şifre!")

# Ana şifre yöneticisi
class PasswordManager(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Şifre Yöneticisi")
        self.geometry("900x700")

        self.show_passwords_flag = False

        # Başlık
        self.title_label = ctk.CTkLabel(self, text="Şifre Yöneticisi", font=("Arial", 32, "bold"))
        self.title_label.pack(pady=20)

        # Arama alanı
        self.search_frame = ctk.CTkFrame(self, corner_radius=15)
        self.search_frame.pack(pady=10, padx=20, fill="x")

        self.search_entry = ctk.CTkEntry(self.search_frame, placeholder_text="Site Ara")
        self.search_entry.pack(side="left", expand=True, fill="x", padx=10, pady=10)

        self.search_button = ctk.CTkButton(self.search_frame, text="Ara", command=self.search_passwords, width=100)
        self.search_button.pack(side="left", padx=10, pady=10)

        # Şifre ekleme alanı
        self.input_frame = ctk.CTkFrame(self, corner_radius=15)
        self.input_frame.pack(pady=10, padx=20, fill="x")

        self.site_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Site Adı")
        self.site_entry.pack(pady=5, padx=20, fill="x")

        self.username_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Kullanıcı Adı")
        self.username_entry.pack(pady=5, padx=20, fill="x")

        self.password_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Şifre", show="*")
        self.password_entry.pack(pady=5, padx=20, fill="x")

        self.button_frame = ctk.CTkFrame(self.input_frame, fg_color="transparent")
        self.button_frame.pack(pady=10)

        self.toggle_button = ctk.CTkButton(self.button_frame, text="Göster", command=self.toggle_password_visibility, width=100)
        self.toggle_button.pack(side="left", padx=10)

        self.add_button = ctk.CTkButton(self.button_frame, text="Şifre Ekle", command=self.save_password, width=100)
        self.add_button.pack(side="left", padx=10)

        # Şifre listeleme alanı
        self.password_frame = ctk.CTkScrollableFrame(self, width=800, height=400, corner_radius=15)
        self.password_frame.pack(pady=20)

        self.refresh_button = ctk.CTkButton(self, text="Yenile", command=self.show_passwords, width=200)
        self.refresh_button.pack(pady=10)

        self.show_passwords()

    def save_password(self):
        site = self.site_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if site and username and password:
            add_password(site, username, password)
            messagebox.showinfo("Başarılı", "Şifre kaydedildi!")
            self.site_entry.delete(0, "end")
            self.username_entry.delete(0, "end")
            self.password_entry.delete(0, "end")
            self.show_passwords()
        else:
            messagebox.showerror("Hata", "Tüm alanları doldurun!")

    def show_passwords(self, filter_text=None):
        for widget in self.password_frame.winfo_children():
            widget.destroy()

        passwords = get_passwords(filter_text)
        for p in passwords:
            password_display = p[3] if self.show_passwords_flag else "●●●●●●"

            frame = ctk.CTkFrame(self.password_frame, corner_radius=15, fg_color="#2a2d3e")
            frame.pack(padx=10, pady=5, fill="x")

            info = ctk.CTkLabel(frame, text=f"ID: {p[0]} | Site: {p[1]} | Kullanıcı: {p[2]} | Şifre: {password_display}",
                                 font=("Arial", 14), anchor="w")
            info.pack(side="left", padx=10, pady=5, expand=True)

            delete_button = ctk.CTkButton(frame, text="Sil", width=60, command=lambda id_=p[0]: self.delete_password_from_list(id_))
            delete_button.pack(side="right", padx=5)

            copy_button = ctk.CTkButton(frame, text="Kopyala", width=60, command=lambda password=p[3]: self.copy_to_clipboard(password))
            copy_button.pack(side="right", padx=5)

    def delete_password_from_list(self, id_):
        confirm = messagebox.askyesno("Onay", "Bu şifreyi silmek istediğinize emin misiniz?")
        if confirm:
            delete_password(id_)
            messagebox.showinfo("Başarılı", "Şifre silindi!")
            self.show_passwords()

    def copy_to_clipboard(self, password):
        self.clipboard_clear()
        self.clipboard_append(password)
        messagebox.showinfo("Başarılı", "Şifre kopyalandı!")

    def toggle_password_visibility(self):
        self.show_passwords_flag = not self.show_passwords_flag
        self.toggle_button.configure(text="Gizle" if self.show_passwords_flag else "Göster")
        self.show_passwords()

    def search_passwords(self):
        filter_text = self.search_entry.get()
        self.show_passwords(filter_text)

# Başlat
if __name__ == "__main__":
    init_db()
    login = LoginScreen()
    login.mainloop()
