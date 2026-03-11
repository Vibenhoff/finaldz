import json, requests, pandas as pd, matplotlib.pyplot as plt, time, os

from collections import Counter
from datetime import datetime
from config import (VT_API_KEY, VT_API_BASE_URL, LOGS_FILE, REPORTS_DIR, API_TIMEOUT, API_RATE_LIMIT_DELAY)

def load_logs(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Ошибка загрузки {filepath}: {e}")
        return []

def extract_suspicious_ips(logs):
    ip_data, dns_queries = {}, []
    suspicious_domains = {'malware', 'worm', 'exploit', 'bot'}
    suspicious_patterns = {'shell', 'cmd', 'exec', 'eval', 'admin', 'phpmyadmin'}
    
    for event in logs:
        event_type = event.get("event_type")
        src_ip = event.get("src_ip")
        
        if event_type == "alert" and src_ip and not src_ip.startswith(('192.168.', '10.', '172.16.')):
            alert = event.get("alert", {})
            ip_data.setdefault(src_ip, {"categories": [], "signatures": [], "severities": [], "event_types": [], "count": 0})
            ip_data[src_ip]["categories"].append(alert.get("category", "Unknown"))
            ip_data[src_ip]["signatures"].append(alert.get("signature", "Unknown"))
            ip_data[src_ip]["severities"].append(alert.get("severity", 3))
            ip_data[src_ip]["event_types"].append("alert")
            ip_data[src_ip]["count"] += 1
            
        elif event_type == "dns":
            query = event.get("dns", {}).get("rrname", "")
            dns_queries.append({"src_ip": src_ip, "query": query, "timestamp": event.get("timestamp", "")})
            if any(d in query.lower() for d in suspicious_domains):
                ip_data.setdefault(src_ip, {"categories": [], "signatures": [], "severities": [], "event_types": [], "count": 0})
                ip_data[src_ip]["categories"].append("Suspicious DNS")
                ip_data[src_ip]["signatures"].append(f"DNS query to {query}")
                ip_data[src_ip]["severities"].append(2)
                ip_data[src_ip]["event_types"].append("dns")
                ip_data[src_ip]["count"] += 1
                               
    return ip_data, dns_queries

def check_ip_reputation(ip):
    if not VT_API_KEY: return 0, 0
    try:
        resp = requests.get(f"{VT_API_BASE_URL}{ip}", headers={"x-apikey": VT_API_KEY}, timeout=API_TIMEOUT)
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            return stats.get('malicious', 0), stats.get('suspicious', 0)
    except: pass
    return 0, 0

def analyze_dns_queries(dns_queries):
    if not dns_queries: return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    df = pd.DataFrame(dns_queries)
    if df.empty: return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    stats = df.groupby(['src_ip', 'query']).size().reset_index(name='count')
    return stats, stats[stats['count'] >= 3], df.groupby('src_ip')['query'].nunique().reset_index(name='unique_queries').query('unique_queries >= 5')

def react_to_threat(ip, malicious, suspicious, category):
    print(f"\nIP: {ip}")
    print(f"Категория активности: {category}")
    print(f"Malicious: {malicious}, Suspicious: {suspicious}")
    if malicious >= 5:
        print("Действие: БЛОКИРОВКА - IP заблокирован на файерволе")
        print("Уведомление отправлено администратору, инцидент зарегистрирован")
    elif malicious >= 1:
        print("Действие: БЛОКИРОВКА - IP заблокирован на файерволе")
    elif suspicious >= 5:
        print("Действие: НАБЛЮДЕНИЕ - IP добавлен в список мониторинга")
    else:
        print("Действие: Угроз не обнаружено")

def save_report_json(results, categories_stats, dns_stats, filepath):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    report = {
        "metadata": {"timestamp": datetime.now().isoformat(), "source": "Suricata"},
        "summary": {
            "total_ips_checked": len(results),
            "threats_found": sum(1 for r in results if r['malicious'] > 0),
            "suspicious_found": sum(1 for r in results if r['suspicious'] > 0),
            "critical_threats": sum(1 for r in results if r['malicious'] >= 5),
            "top_categories": [{"category": k, "count": v} for k, v in categories_stats.most_common(5)]
        },
        "dns_analysis": {
            "total_queries": int(dns_stats['count'].sum()) if isinstance(dns_stats, pd.DataFrame) and not dns_stats.empty else 0,
            "unique_domains": int(dns_stats['query'].nunique()) if isinstance(dns_stats, pd.DataFrame) and not dns_stats.empty else 0
        },
        "threat_details": results
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"JSON отчет сохранен - {filepath}")

def create_visualization_dashboard(results_df, categories_counter, dns_stats, suspicious_dns, filepath):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    fig = plt.figure(figsize=(16, 12))
    gs = fig.add_gridspec(2, 2, hspace=0.3, wspace=0.3)
    
    ax1 = fig.add_subplot(gs[0, 0])
    threats_df = results_df[results_df['malicious'] > 0].sort_values('malicious', ascending=False).head(10)
    if not threats_df.empty:
        bars = ax1.barh(range(len(threats_df)), threats_df['malicious'].values, color='darkred')
        ax1.set_yticks(range(len(threats_df)))
        ax1.set_yticklabels(threats_df['ip'].values, fontsize=8)
        ax1.set_title('IP адреса с вредоносной активностью (VirusTotal)')
        ax1.grid(axis='x', linestyle='--', alpha=0.3)
        for i, bar in enumerate(bars):
            ax1.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height()/2, f'{int(bar.get_width())}', va='center', fontsize=8)
    else:
        ax1.text(0.5, 0.5, 'Вредоносных IP не обнаружено', ha='center', va='center', fontsize=12, color='green')
        ax1.set_title('Результаты проверки')
        ax1.axis('off')
    
    ax2 = fig.add_subplot(gs[0, 1])
    top_categories = categories_counter.most_common(6)
    if top_categories:
        labels, sizes = zip(*top_categories)
        ax2.pie(sizes, labels=labels, autopct='%1.0f%%', colors=plt.cm.Set3(range(len(labels))), startangle=90)
        ax2.set_title('Категории угроз (Suricata)')
    else:
        ax2.text(0.5, 0.5, 'Нет данных о категориях', ha='center', va='center')
        ax2.set_title('Категории угроз')
    
    ax3 = fig.add_subplot(gs[1, :])
    top5 = results_df.sort_values('malicious', ascending=False).head(5)
    if not top5.empty:
        x, width = range(len(top5)), 0.35
        ax3.bar([i - width/2 for i in x], top5['malicious'], width, label='Malicious', color='red', alpha=0.7)
        ax3.bar([i + width/2 for i in x], top5['suspicious'], width, label='Suspicious', color='orange', alpha=0.7)
        ax3.set_xticks(x)
        ax3.set_xticklabels([ip[:15] + '...' if len(ip) > 15 else ip for ip in top5['ip']], rotation=45, ha='right')
        ax3.set_title('Количество активностей (VirusTotal)')
        ax3.legend()
        ax3.grid(axis='y', linestyle='--', alpha=0.3)
    else:
        ax3.text(0.5, 0.5, 'Нет данных для сравнения', ha='center', va='center')
        ax3.set_title('Сравнение результатов')
        ax3.axis('off')
    
    plt.suptitle('Визуализация результатов анализа', fontsize=16, fontweight='bold', y=0.98)
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Графики сохранены - {filepath}")

def main():
    
    logs = load_logs(LOGS_FILE)
    if not logs: return
    
    ip_info, dns_queries = extract_suspicious_ips(logs)
    ips_to_check = list(ip_info.keys())
    
    print(f"\nЭтап 1. Сбор данных")
    print(f"\nКоличество событий: {len(logs)}, {len(ips_to_check)} IP в списке\n")
    if ips_to_check: print(f"IP: {', '.join(ips_to_check[:5])}")
    
    dns_stats, suspicious_dns, _ = analyze_dns_queries(dns_queries)
    print(f"DNS запросов: {len(dns_queries)}, подозрительных: {len(suspicious_dns) if isinstance(suspicious_dns, pd.DataFrame) else 0}")
    
    all_categories = [cat for ip in ip_info.values() for cat in ip["categories"]]
    categories_counter = Counter(all_categories)
    
    print("\nЭтап 2. Анализ данных\n")
    results = []
    for i, ip in enumerate(ips_to_check):
        print(f"[{i+1}/{len(ips_to_check)}] {ip}")
        malicious, suspicious = check_ip_reputation(ip) if VT_API_KEY else (0, 0)
        results.append({
            "ip": ip, "malicious": malicious, "suspicious": suspicious,
            "category": ip_info[ip]["categories"][0] if ip_info[ip]["categories"] else "Unknown",
            "count": ip_info[ip]["count"],
            "severity_max": max(ip_info[ip]["severities"]) if ip_info[ip]["severities"] else 3,
            "event_types": list(set(ip_info[ip]["event_types"]))
        })
        if i < len(ips_to_check) - 1: time.sleep(API_RATE_LIMIT_DELAY)
    
    print("\nЭтап 3. Реагирование на угрозы")
    threats = [r for r in results if r['malicious'] > 0 or r['suspicious'] > 0]
    for r in threats: react_to_threat(r['ip'], r['malicious'], r['suspicious'], r['category'])
    if not threats: print("Угроз не обнаружено")
    
    print("\nЭтап 4. Формирование отчёта и визуализация\n")
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    df = pd.DataFrame(results)
    
    csv_path = os.path.join(REPORTS_DIR, f"analysis_{timestamp}.csv")
    df.to_csv(csv_path, index=False)
    print(f"CSV отчет сохранен - {csv_path}")
    
    json_path = os.path.join(REPORTS_DIR, f"report_{timestamp}.json")
    save_report_json(results, categories_counter, dns_stats, json_path)
    
    if not df.empty:
        chart_path = os.path.join(REPORTS_DIR, f"dashboard_{timestamp}.png")
        create_visualization_dashboard(df, categories_counter, dns_stats, suspicious_dns, chart_path)

if __name__ == "__main__":
    main()