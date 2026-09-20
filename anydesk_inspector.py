import os
import re
import sys
import json
import time
import socket
import datetime
import urllib.request
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading

def is_private_ip(ip_str):
    """Проверка, является ли IP локальным/приватным."""
    try:
        parts = [int(p) for p in ip_str.split('.')]
        if len(parts) != 4:
            return True
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        return False
    except Exception:
        return True

def get_geoip_info(ip):
    """Запрос гео-информации по IP через публичный API."""
    if is_private_ip(ip):
        return {"status": "private", "message": "Локальный / Приватный IP"}
    
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'AnyDesk-Inspector/1.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data
    except Exception as e:
        return {"status": "fail", "message": str(e), "query": ip}

def get_anydesk_log_paths():
    """Поиск путей к логам AnyDesk в системе Windows."""
    paths = []
    
    # 1. AppData (пользовательская/портативная версия)
    appdata = os.getenv('APPDATA')
    if appdata:
        p1 = os.path.join(appdata, 'AnyDesk', 'ad.trace')
        p2 = os.path.join(appdata, 'AnyDesk', 'connection_trace.txt')
        if os.path.exists(p1): paths.append(p1)
        if os.path.exists(p2): paths.append(p2)
        
    # 2. ProgramData (установленная служба AnyDesk)
    programdata = os.getenv('PROGRAMDATA')
    if programdata:
        p3 = os.path.join(programdata, 'AnyDesk', 'ad_svc.trace')
        p4 = os.path.join(programdata, 'AnyDesk', 'ad.trace')
        if os.path.exists(p3): paths.append(p3)
        if os.path.exists(p4): paths.append(p4)
        
    return list(set(paths))

def parse_anydesk_logs():
    """Парсинг лог-файлов AnyDesk для поиска входящих сессий и IP."""
    log_files = get_anydesk_log_paths()
    findings = []
    
    # Регулярные выражения для поиска AnyDesk ID, IP и событий подключения
    ip_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    id_pattern = re.compile(r'Logged in from\s+(\d+)|Incoming session request:\s+(\d+)|User-ID:\s+(\d+)|ad:(\d{9,10})')
    
    for filepath in log_files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for idx, line in enumerate(lines):
                # Ищем упоминания IP и сессий
                if any(k in line.lower() for k in ['logged in', 'incoming session', 'external ip', 'connect', 'relay', 'p2p']):
                    ips = ip_pattern.findall(line)
                    ids = id_pattern.findall(line)
                    
                    extracted_ids = [item for sub in ids for item in sub if item]
                    
                    for ip in ips:
                        if not is_private_ip(ip):
                            findings.append({
                                "source_file": filepath,
                                "line_number": idx + 1,
                                "raw_line": line.strip(),
                                "ip": ip,
                                "anydesk_ids": extracted_ids,
                                "time_str": line[:25] if len(line) >= 25 else ""
                            })
        except Exception as e:
            print(f"Ошибка чтения {filepath}: {e}")
            
    return findings

def get_active_anydesk_connections():
    """Получение активных сетевых соединений процесса AnyDesk через netstat / PowerShell."""
    import subprocess
    active_ips = set()
    try:
        cmd = 'powershell -NoProfile -Command "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue; if ($p.ProcessName -like \'*anydesk*\') { $_.RemoteAddress + \':\' + $_.RemotePort } }"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8)
        lines = result.stdout.strip().splitlines()
        for line in lines:
            line = line.strip()
            if ':' in line:
                ip = line.split(':')[0]
                if not is_private_ip(ip):
                    active_ips.add(line)
    except Exception as e:
        print(f"Ошибка проверки активных соединений: {e}")
        
    return list(active_ips)

class AnyDeskInspectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AnyDesk Session & Connection Inspector")
        self.root.geometry("900x600")
        self.root.minsize(750, 450)
        
        self.results_data = []
        self._setup_ui()
        
    def _setup_ui(self):
        # Панель управления
        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(fill=tk.X)
        
        self.btn_scan_logs = ttk.Button(top_frame, text="🔍 Сканировать логи AnyDesk", command=self.start_log_scan)
        self.btn_scan_logs.pack(side=tk.LEFT, padx=5)
        
        self.btn_scan_active = ttk.Button(top_frame, text="📡 Проверить активные соединения", command=self.start_active_scan)
        self.btn_scan_active.pack(side=tk.LEFT, padx=5)
        
        self.btn_export_html = ttk.Button(top_frame, text="📄 Сохранить отчет (HTML)", command=self.export_html_report)
        self.btn_export_html.pack(side=tk.RIGHT, padx=5)
        
        self.btn_export_txt = ttk.Button(top_frame, text="💾 Сохранить отчет (TXT)", command=self.export_txt_report)
        self.btn_export_txt.pack(side=tk.RIGHT, padx=5)

        # Статус бар
        self.status_var = tk.StringVar(value="Готов к сканированию.")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=5)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Таблица результатов
        columns = ("type", "ip", "location", "isp", "org", "details")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        
        self.tree.heading("type", text="Тип")
        self.tree.heading("ip", text="IP-адрес")
        self.tree.heading("location", text="Локация (Страна / Город)")
        self.tree.heading("isp", text="Провайдер (ISP)")
        self.tree.heading("org", text="Организация / AS")
        self.tree.heading("details", text="Дополнительно")

        self.tree.column("type", width=90, anchor=tk.CENTER)
        self.tree.column("ip", width=120, anchor=tk.CENTER)
        self.tree.column("location", width=170)
        self.tree.column("isp", width=160)
        self.tree.column("org", width=160)
        self.tree.column("details", width=180)

        scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def set_status(self, text):
        self.status_var.set(text)
        self.root.update_idletasks()

    def start_log_scan(self):
        threading.Thread(target=self._run_log_scan, daemon=True).start()

    def start_active_scan(self):
        threading.Thread(target=self._run_active_scan, daemon=True).start()

    def _run_log_scan(self):
        self.set_status("Поиск и анализ логов AnyDesk...")
        findings = parse_anydesk_logs()
        
        if not findings:
            self.set_status("Логи AnyDesk не найдены или в них нет внешних IP-адресов.")
            messagebox.showinfo("Результат", "Логи AnyDesk не найдены или внешние подключения отсутствуют.")
            return

        unique_ips = {}
        for f in findings:
            ip = f["ip"]
            if ip not in unique_ips:
                unique_ips[ip] = f
        
        self.set_status(f"Найдено {len(unique_ips)} уникальных IP в логах. Запрос GeoIP...")
        
        for ip, item in unique_ips.items():
            geo = get_geoip_info(ip)
            item["geo"] = geo
            self.results_data.append(item)
            
            loc = f"{geo.get('country', '')}, {geo.get('city', '')}" if geo.get('status') == 'success' else 'Не определено'
            isp = geo.get('isp', 'Н/Д')
            org = geo.get('org', geo.get('as', 'Н/Д'))
            ids = ", ".join(item.get("anydesk_ids", []))
            details = f"AnyDesk ID: {ids}" if ids else item.get("source_file", "")
            
            self.tree.insert("", tk.END, values=("Лог", ip, loc, isp, org, details))
            time.sleep(0.3) # Ограничение частоты запросов к бесплатному API
            
        self.set_status(f"Сканирование завершено. Обработано {len(unique_ips)} IP.")

    def _run_active_scan(self):
        self.set_status("Проверка активных сетевых соединений AnyDesk...")
        active_conns = get_active_anydesk_connections()
        
        if not active_conns:
            self.set_status("Активных внешних соединений AnyDesk не обнаружено.")
            messagebox.showinfo("Результат", "Активных сетевых соединений AnyDesk не обнаружено.\nУбедитесь, что сессия запущена.")
            return

        self.set_status(f"Найдено {len(active_conns)} активных подключений. Запрос GeoIP...")
        
        for conn_str in active_conns:
            ip = conn_str.split(':')[0]
            geo = get_geoip_info(ip)
            item = {
                "source_file": "Active Connection",
                "ip": ip,
                "raw_line": f"Active TCP: {conn_str}",
                "geo": geo,
                "time_str": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.results_data.append(item)
            
            loc = f"{geo.get('country', '')}, {geo.get('city', '')}" if geo.get('status') == 'success' else 'Не определено'
            isp = geo.get('isp', 'Н/Д')
            org = geo.get('org', geo.get('as', 'Н/Д'))
            
            # Проверка релей-сервера AnyDesk
            note = ""
            if "anydesk" in isp.lower() or "anydesk" in org.lower() or "hetzner" in org.lower() or "ovh" in org.lower():
                note = " (Вероятно сервер Relay)"
                
            self.tree.insert("", tk.END, values=("Активное", conn_str, loc, isp, org + note, "В реальном времени"))
            time.sleep(0.3)

        self.set_status(f"Активные соединения проверены: {len(active_conns)} найдено.")

    def export_html_report(self):
        if not self.results_data:
            messagebox.showwarning("Внимание", "Нет данных для отчета. Сначала запустите сканирование.")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Document", "*.html")],
            initialfile=f"anydesk_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        if not file_path:
            return

        html_content = f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>AnyDesk Connection & Security Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 30px; background: #f8f9fa; color: #333; }}
        h1 {{ color: #1a73e8; margin-bottom: 5px; }}
        .meta {{ color: #666; font-size: 14px; margin-bottom: 25px; }}
        table {{ width: 100%; border-collapse: collapse; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-radius: 6px; overflow: hidden; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #e0e0e0; font-size: 14px; }}
        th {{ background-color: #f1f3f4; font-weight: 600; color: #202124; }}
        tr:hover {{ background-color: #f8f9fa; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-log {{ background: #e8f0fe; color: #1a73e8; }}
        .badge-active {{ background: #e6f4ea; color: #137333; }}
        .warning-box {{ background: #fef7e0; border-left: 4px solid #f9ab00; padding: 12px 15px; margin-top: 20px; font-size: 13px; }}
    </style>
</head>
<body>
    <h1>Отчет о сессиях и сетевых подключениях AnyDesk</h1>
    <div class="meta">Сформирован: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>

    <table>
        <thead>
            <tr>
                <th>Источник</th>
                <th>IP-адрес</th>
                <th>Геолокация</th>
                <th>Провайдер (ISP)</th>
                <th>Организация / AS</th>
                <th>Координаты / Временная зона</th>
                <th>Детали</th>
            </tr>
        </thead>
        <tbody>
"""
        for item in self.results_data:
            geo = item.get("geo", {})
            source = item.get("source_file", "")
            is_active = "Active" in source
            badge_class = "badge-active" if is_active else "badge-log"
            badge_text = "Активное" if is_active else "Лог"
            
            loc = f"{geo.get('country', '-')}, {geo.get('regionName', '')}, {geo.get('city', '-')}" if geo.get("status") == "success" else "Не определено"
            isp = geo.get("isp", "-")
            org = geo.get("org", geo.get("as", "-"))
            coords = f"{geo.get('lat', '-')}, {geo.get('lon', '-')} ({geo.get('timezone', '-')})" if geo.get("status") == "success" else "-"
            details = item.get("raw_line", "")
            
            html_content += f"""
            <tr>
                <td><span class="badge {badge_class}">{badge_text}</span></td>
                <td><strong>{item.get('ip', '-')}</strong></td>
                <td>{loc}</td>
                <td>{isp}</td>
                <td>{org}</td>
                <td>{coords}</td>
                <td style="font-family: monospace; font-size: 12px; word-break: break-all;">{details}</td>
            </tr>
            """

        html_content += """
        </tbody>
    </table>

    <div class="warning-box">
        <strong>Примечание по интерпретации данных:</strong><br>
        1. Если в качестве организации указан дата-центр или AnyDesk Software GmbH (релей), соединение шло через промежуточный сервер AnyDesk.<br>
        2. При использовании злоумышленником VPN или прокси-серверов геолокация отражает местоположение выходной ноды VPN, а не физический адрес человека.
    </div>
</body>
</html>
"""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        messagebox.showinfo("Успех", f"Отчет сохранен в файл:\n{file_path}")

    def export_txt_report(self):
        if not self.results_data:
            messagebox.showwarning("Внимание", "Нет данных для отчета. Сначала запустите сканирование.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text File", "*.txt")],
            initialfile=f"anydesk_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if not file_path:
            return

        lines = [
            "==================================================",
            "   ОТЧЕТ ПО ПОДКЛЮЧЕНИЯМ ANYDESK",
            f"   Дата формирования: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "==================================================\n"
        ]
        
        for idx, item in enumerate(self.results_data, 1):
            geo = item.get("geo", {})
            lines.append(f"[{idx}] IP: {item.get('ip')}")
            lines.append(f"    Источник: {item.get('source_file')}")
            if geo.get("status") == "success":
                lines.append(f"    Локация: {geo.get('country')} / {geo.get('regionName')} / {geo.get('city')}")
                lines.append(f"    Провайдер: {geo.get('isp')}")
                lines.append(f"    Организация: {geo.get('org')}")
                lines.append(f"    Координаты: {geo.get('lat')}, {geo.get('lon')} (Часовой пояс: {geo.get('timezone')})")
            else:
                lines.append(f"    GeoIP: {geo.get('message', 'Не удалось определить')}")
            lines.append(f"    Исходная строка: {item.get('raw_line')}")
            lines.append("-" * 50)
            
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        messagebox.showinfo("Успех", f"Текстовый отчет сохранен:\n{file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AnyDeskInspectorApp(root)
    root.mainloop()
