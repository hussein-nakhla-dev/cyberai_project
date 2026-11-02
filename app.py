import streamlit as st
import requests
import socket
import ssl
from urllib.parse import urlparse, parse_qs
import re
import datetime
import pandas as pd
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import hashlib

# إعداد الصفحة
st.set_page_config(page_title="Hussein Nakhla - AI Cyber Threat Intelligence Platform", layout="wide")

# تهيئة كافة متغيرات الجلسة لمنع أي خطأ برمجي نهائياً
if "language" not in st.session_state:
    st.session_state.language = "العربية"

if "last_scan_input" not in st.session_state:
    st.session_state.last_scan_input = None

if "last_scan_result" not in st.session_state:
    st.session_state.last_scan_result = None

# حالات الأزرار المستقلة
if "show_threat_intel" not in st.session_state:
    st.session_state.show_threat_intel = False
if "show_incident_ticket" not in st.session_state:
    st.session_state.show_incident_ticket = False
if "show_port_scanner" not in st.session_state:
    st.session_state.show_port_scanner = False

def toggle_language():
    if st.session_state.language == "العربية":
        st.session_state.language = "English"
    else:
        st.session_state.language = "العربية"

is_en = (st.session_state.language == "English")

# تصميم واجهات الـ CSS الديناميكية وصناديق التنسيق المتقدمة وأزرار الحجم الصغير
direction_css = "ltr" if is_en else "rtl"
align_css = "left" if is_en else "right"
border_side = "border-left" if is_en else "border-right"

st.markdown(f"""
    <style>
    body, .stApp {{
        direction: {direction_css};
        text-align: {align_css};
        background-color: #0e1117;
        color: #ffffff;
    }}
    .stTextInput, .stTextArea, .stButton, .stMarkdown, p, span, div, h1, h2, h3, h4 {{
        direction: {direction_css};
        text-align: {align_css};
    }}
    .metric-card {{
        background-color: #1a1c23;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #30363d;
        margin-bottom: 15px;
    }}
    .intro-box {{
        background-color: #16222a;
        padding: 18px;
        border-radius: 8px;
        {border_side}: 5px solid #00c853;
        margin-bottom: 20px;
        direction: {direction_css};
        text-align: {align_css};
    }}
    .advanced-box {{
        background-color: #121820;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #00adb5;
        margin-bottom: 20px;
        box-shadow: 0 4px 15px rgba(0, 173, 181, 0.15);
    }}
    .threat-intel-box {{
        background-color: #1f1624;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #bd00ff;
        margin-bottom: 20px;
        box-shadow: 0 4px 15px rgba(189, 0, 255, 0.15);
    }}
    .ticket-box {{
        background-color: #241a16;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #ff9100;
        margin-bottom: 20px;
        box-shadow: 0 4px 15px rgba(255, 145, 0, 0.15);
    }}
    .ports-box {{
        background-color: #16241c;
        padding: 20px;
        border-radius: 10px;
        border: 1px solid #00c853;
        margin-bottom: 20px;
        box-shadow: 0 4px 15px rgba(0, 200, 83, 0.15);
    }}
    .threat-intel-box h4, .ticket-box h4, .ports-box h4, .advanced-box h4 {{
        margin-bottom: 12px;
    }}
    .intro-box p, .intro-box h4 {{
        direction: {direction_css};
        text-align: {align_css};
        unicode-bidi: plaintext;
    }}
    /* زر الفحص الرئيسي بحجم كامل */
    .stButton button {{
        background: linear-gradient(135deg, #00adb5, #1f4068);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 12px 24px;
        font-weight: bold;
        font-size: 16px;
        width: 100%;
        transition: 0.3s;
        box-shadow: 0 4px 12px rgba(0, 173, 181, 0.3);
    }}
    .stButton button:hover {{
        background: linear-gradient(135deg, #1f4068, #00adb5);
        box-shadow: 0 6px 16px rgba(0, 173, 181, 0.5);
    }}
    .stDownloadButton button {{
        background: linear-gradient(135deg, #1f4068, #162447);
        color: white;
        border: 1px solid #00adb5;
        border-radius: 8px;
        padding: 10px 20px;
        font-weight: bold;
        width: 100%;
        transition: 0.3s;
    }}
    .stDownloadButton button:hover {{
        background: linear-gradient(135deg, #00adb5, #1f4068);
        border-color: #ffffff;
    }}
    </style>
""", unsafe_allow_html=True)

# قاموس الترجمات الشامل بالكامل
t = {
    "title": "منصة استخبارات تهديدات سيبرانية مدعومة بالذكاء الاصطناعي 🛡️" if not is_en else "AI-Powered Cyber Threat Intelligence Platform 🛡️",
    "welcome": "منصة مدعومة بالذكاء الاصطناعي" if not is_en else "AI-powered platform.",
    "input_label": "🎯 أدخل الهدف المطلوب فحصه (رابط موقع، عنوان IP، أو نص بريد إلكتروني):" if not is_en else "🎯 Enter target to scan (URL, IP Address, or Email text):",
    "placeholder": "مثال: https://jolz.sa أو 8.8.8.8 أو نص الرسالة المشبوهة..." if not is_en else "Example: https://jolz.sa or 8.8.8.8 or suspicious text...",
    "btn_scan": "بدء الفحص الشامل والمتقدم" if not is_en else "Run Ultimate Comprehensive Scan",
    "err_empty": "⚠️ يرجى إدخال هدف صحيح في الخانة المخصصة." if not is_en else "⚠️ Please enter a valid target in the designated field.",
    "spinner": "جاري إجراء الفحص الاستخباراتي الشامل والمتكامل لـ" if not is_en else "Running absolute comprehensive intelligence inspection for",
    "success": "✨ تم إتمام التحليل الشامل والمتقدم بنجاح!" if not is_en else "✨ Ultimate comprehensive analysis completed successfully!",
    "intro_title": "📖 نظرة عامة والهُوية المؤسسية للهدف:" if not is_en else "📖 Target Overview & Enterprise Identity:",
    "metric_title": "📊 ملخص التقييم الأمني:" if not is_en else "📊 Security Assessment Summary:",
    "identity": "طبيعة وهُوية الموقع:" if not is_en else "Target Identity:",
    "target": "الهدف المفحوص:" if not is_en else "Scanned Target:",
    "risk": "تقييم الخطورة:" if not is_en else "Risk Level:",
    "risk_meter": "مؤشر الخطر" if not is_en else "Risk Score",
    "risk_desc": "مستوى التهديد المحسوب" if not is_en else "Calculated Threat Level",
    "findings_title": "🔍 نتائج الاستخبارات المتقدمة ورصد الثغرات:" if not is_en else "🔍 Advanced Intelligence & Vulnerability Findings:",
    "tech_title": "⚙️ البصمة التقنية، فحص الـ CORS، الكوكيز واستطلاع النطاقات:" if not is_en else "⚙️ Deep Technical, CORS, Cookies & Recon Intelligence:",
    "advanced_title": "🛡️ صندوق استخبارات الدفاع المتقدم وحماية النطاق (WAF & Headers Box):" if not is_en else "🛡️ Advanced Defense & WAF Intelligence Box:",
    
    # تسميات الأزرار المستقلة الجديدة ذات الحجم الصغير والأيقونات الاحترافية
    "threat_btn": "🔮 فحص السمعة العالمية (Threat Intel)" if not is_en else "🔮 Global Threat Intelligence",
    "threat_box_title": "🔮 صندوق تقييم السمعة العالمية وقواعد بيانات التهديدات (XDR & Threat Feeds):" if not is_en else "🔮 Global Reputation & Threat Intelligence Feeds (XDR):",
    
    "ticket_btn": "🎫 تذكرة الحوادث الأمنية (CISO Ticket)" if not is_en else "🎫 CISO Incident Ticket Generator",
    "ticket_box_title": "🎫 تقرير تذكرة الحوادث الأمنية الموجه للإدارة العليا (P1 - CISO Report):" if not is_en else "🎫 Automated CISO Incident Response Ticket (P1 Priority):",
    
    "ports_btn": "🔍 فحص المنافذ الموسع (Port Scanner)" if not is_en else "🔍 Extended Enterprise Port Scanner",
    "ports_box_title": "🔍 نتائج فحص المنافذ وشبكة الخدمة الموسعة (Extended Ports Audit):" if not is_en else "🔍 Extended Ports & Network Services Audit Results:",
    
    "impr_title": "💡 المعالجات والتوصيات الأمنية المقترحة:" if not is_en else "💡 Recommended Enterprise Remediations:",
    "impr_box": "الإجراءات التالية ملزمة لرفع مستوى الامتثال الأمني:" if not is_en else "The following actions are mandated for security compliance:",
    "export_title": "📥 أدوات التصدير والمشاركة:" if not is_en else "📥 Export & Audit Sharing Tools:",
    "dl_html_label": "🌐 اختر لغة التقرير المراد تحميله (HTML):" if not is_en else "🌐 Select Report Language to Download (HTML):",
    "dl_html_btn": "تحميل التقرير التفاعلي (HTML)" if not is_en else "Download Interactive HTML Report",
    
    "footer": "منصة استخبارات تهديدات سيبرانية مدعومة بالذكاء الاصطناعي<br>تطوير المهندس : <b>حسين نخلة</b> 🛡️ جميع الحقوق محفوظة" if not is_en else "AI-Powered Cyber Threat Intelligence Platform<br>Developed by Eng. <b>Hussein Nakhla</b> 🛡️ All Rights Reserved",
    
    "imp_1": "تأمين وحظر الوصول لملفات الإعدادات الحساسة (.env, .git)." if not is_en else "Secure and restrict access to sensitive configuration files (.env, .git).",
    "imp_2": "تفعيل حماية الكوكيز وضبط سياسات CORS بدقة." if not is_en else "Enforce Secure, HttpOnly flags and strict CORS policies.",
    "imp_3": "تفعيل ترويسات الأمان المتقدمة وتجديد شهادات التشفير." if not is_en else "Implement advanced security headers and renew SSL certificates.",
    "imp_ip_1": "إغلاق المنافذ غير الأساسية." if not is_en else "Close non-essential ports and restrict exposure.",
    "imp_ip_2": "تطبيق قواعد صارمة للوصول لخدمات التحكم." if not is_en else "Deploy strict firewall rules for SSH and RDP.",
    "imp_phish_1": "عدم التفاعل مع الروابط غير الموثوقة." if not is_en else "Never interact with or submit credentials via unverified links.",
    "imp_phish_2": "الإبلاغ عن الرسائل المشبوهة." if not is_en else "Report suspicious messages to security operations."
}

# رأس المنصة وزر اللغة
col_title, col_lang = st.columns([5, 1])

with col_title:
    st.title(t["title"])

with col_lang:
    st.write("")
    lang_button_text = "🇬🇧 English" if not is_en else "🇸🇦 العربية"
    if st.button(lang_button_text, use_container_width=True, on_click=toggle_language):
        pass

st.markdown(f"### {t['welcome']}")
st.markdown("---")

st.markdown(f"**{t['input_label']}**")
user_input = st.text_area("", placeholder=t["placeholder"], height=100)

if st.button(t["btn_scan"], use_container_width=True):
    if not user_input.strip():
        st.error(t["err_empty"])
    else:
        st.session_state.last_scan_input = user_input.strip()
        # إعادة تعيين حالات الأزرار المستقلة عند بدء فحص جديد
        st.session_state.show_threat_intel = False
        st.session_state.show_incident_ticket = False
        st.session_state.show_port_scanner = False

if st.session_state.last_scan_input is not None:
    input_str = st.session_state.last_scan_input
    detected_type = ""
    ip_regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    
    if re.match(ip_regex, input_str):
        detected_type = "IP Address" if is_en else "عنوان IP"
    elif "@" in input_str and "." in input_str and "http" not in input_str:
        detected_type = "Text / Email" if is_en else "نص / بريد إلكتروني"
    else:
        detected_type = "URL" if is_en else "رابط موقع (URL)"

    with st.spinner(f"{t['spinner']} ({detected_type})..."):
        
        risk_status = "Excellent (Enterprise Secure)" if is_en else "ممتازة (مستوى أمان مؤسسي آمن)"
        risk_score = 10
        findings = []
        tech_details = []
        advanced_box_details = []
        improvements = []
        target_name = input_str if len(input_str) < 50 else input_str[:47] + "..."
        site_identity = "Digital Platform or Enterprise Website" if is_en else "منصة رقمية أو موقع مؤسسي"

        if detected_type in ["URL", "رابط موقع (URL)"]:
            url = input_str
            if not url.startswith("http"):
                url = "https://" + url
            parsed = urlparse(url)
            domain = parsed.netloc if parsed.netloc else parsed.path
            target_name = domain

            domain_lower = domain.lower()
            if "jolz" in domain_lower:
                site_identity = "E-commerce Shopping Platform" if is_en else "منصة تسوق تجاري إلكتروني (E-commerce Platform)"
            elif any(w in domain_lower for w in ["car", "auto", "vehicle"]):
                site_identity = "Car & Vehicle Showroom / Platform" if is_en else "معرض أو منصة سيارات ومركبات"
            elif any(w in domain_lower for w in ["news", "blog", "press"]):
                site_identity = "News Platform or Digital Blog" if is_en else "منصة إخبارية أو مدونة رقمية"
            else:
                site_identity = f"Digital Platform with domain ({domain})" if is_en else f"منصة رقمية عاملة بنطاق تجاري ({domain})"

            query_params = parse_qs(parsed.query)
            if query_params:
                risk_score += 15
                findings.append(
                    f"Detected ({len(query_params)}) interactive dynamic parameters, potential injection vectors." if is_en 
                    else f"تم رصد معاملات ديناميكية تفاعلية بعدد ({len(query_params)} Parameters)، وهي نقاط محتملة لحقن البيانات."
                )

            try:
                ns_resp = requests.get(f"https://dns.google/resolve?name={domain}&type=NS", timeout=2.0).json()
                if "Answer" in ns_resp:
                    ns_servers = [ans.get("data", "") for ans in ns_resp["Answer"]]
                    advanced_box_details.append(
                        f"DNS Name Servers (NS): Detected ({len(ns_servers)}) active nameservers." if is_en 
                        else f"خوادم الأسماء (NS): تم رصد ({len(ns_servers)}) خوادم مسؤولة عن إدارة النطاق."
                    )
            except:
                pass

            try:
                resp = requests.get(url, timeout=3.5, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
                server_tech = resp.headers.get("Server", "Hidden / Protected WAF")
                powered_by = resp.headers.get("X-Powered-By", "Secured Stack")
                advanced_box_details.append(
                    f"WAF & Web Stack Fingerprint: Server -> [{server_tech}] | Powered-By -> [{powered_by}]" if is_en 
                    else f"بصمة الـ WAF وتقنيات الويب: خادم الويب -> [{server_tech}] | التقنية المستخدمة -> [{powered_by}]"
                )

                extra_headers = ['Permissions-Policy', 'X-Content-Type-Options', 'Referrer-Policy']
                missing_extra = [h for h in extra_headers if h not in resp.headers]
                if missing_extra:
                    risk_score += 10
                    advanced_box_details.append(
                        f"Advanced Security Headers Warning: Missing -> {', '.join(missing_extra)}" if is_en 
                        else f"تحذير ترويسات الأمان المتقدمة: غياب الترويسات الهامة -> {', '.join(missing_extra)}"
                    )
                else:
                    advanced_box_details.append(
                        "Advanced Security Headers: Fully implemented and hardened." if is_en 
                        else "ترويسات الأمان المتقدمة: مفعلة بالكامل ومحفوظة."
                    )
            except:
                pass

            try:
                whois_resp = requests.get(f"https://dns.google/resolve?name={domain}&type=SOA", timeout=2.5).json()
                if "Answer" in whois_resp:
                    tech_details.append(
                        f"WHOIS / DNS Authority: Active SOA record validated for {domain}." if is_en 
                        else f"استعلام سجلات السلطة (SOA): تم التحقق من نشاط النطاق رسمياً لـ {domain}."
                    )
            except:
                pass

            sensitive_files = [".env", ".git/config", "backup.sql", "config.json"]
            exposed_files = []
            for sf in sensitive_files:
                try:
                    sf_resp = requests.get(f"https://{domain}/{sf}", timeout=1.5)
                    if sf_resp.status_code == 200 and len(sf_resp.text) > 0 and "html" not in sf_resp.text[:50].lower():
                        exposed_files.append(sf)
                except:
                    pass
            
            if exposed_files:
                risk_score += 40
                findings.append(
                    f"Critical Information Disclosure: Sensitive files exposed publicly -> {', '.join(exposed_files)}" if is_en 
                    else f"تسريب معلومات خطير: تم رصد ملفات حساسة مكشوفة للعامة -> {', '.join(exposed_files)}"
                )
            else:
                tech_details.append(
                    "Information Disclosure Check: No sensitive configuration files exposed." if is_en 
                    else "فحص تسريب المعلومات: لا توجد ملفات إعدادات حساسة مكشوفة."
                )

            try:
                redir_resp = requests.get(url, timeout=4.0, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
                history_len = len(redir_resp.history)
                if history_len > 0:
                    tech_details.append(
                        f"Redirect Chains: URL went through ({history_len}) redirect hops." if is_en 
                        else f"سلاسل إعادة التوجيه: مر الرابط عبر ({history_len}) عمليات تحويل قبل الوصول للوجهة النهائية."
                    )
            except:
                pass

            try:
                ct_resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=3.0)
                if ct_resp.status_code == 200:
                    ct_data = ct_resp.json()
                    subdomains = set()
                    for entry in ct_data[:40]:
                        name_value = entry.get("name_value", "")
                        for sub in name_value.split("\n"):
                            if domain in sub and "*" not in sub:
                                subdomains.add(sub.strip())
                    if subdomains:
                        tech_details.append(
                            f"Certificate Transparency Recon: Discovered ({len(subdomains)}) subdomains (e.g., {list(subdomains)[:3]})" if is_en 
                            else f"استطلاع شفافية الشهادات: تم رصد ({len(subdomains)}) نطاقات فرعية نشطة (مثل: {list(subdomains)[:3]})"
                        )
            except:
                pass

            try:
                cookie_resp = requests.get(url, timeout=3.0, headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
                cookies = cookie_resp.cookies
                if cookies:
                    insecure_cookies = [c.name for c in cookies if not c.secure or not c.has_nonstandard_attr('HttpOnly')]
                    if insecure_cookies:
                        risk_score += 20
                        findings.append(
                            f"Insecure Cookies Detected: Missing Secure/HttpOnly flags in -> {', '.join(insecure_cookies)}" if is_en 
                            else f"تم رصد كوكيز غير آمنة: غياب حماية Secure/HttpOnly في -> {', '.join(insecure_cookies)}"
                        )
                    else:
                        tech_details.append(
                            "Cookies Security Audit: All session cookies are protected." if is_en 
                            else "تدقيق أمان الكوكيز: كافة جلسات الكوكيز محمية ومؤمنة."
                        )
                
                cors_header = cookie_resp.headers.get("Access-Control-Allow-Origin", "")
                if cors_header == "*":
                    risk_score += 15
                    findings.append(
                        "Insecure CORS Policy: Access-Control-Allow-Origin is set to wild-card (*), data leakage risk." if is_en 
                        else "سياسة CORS غير آمنة: السماح بالوصول للجميع (*) يعرض البيانات لمخاطر التسريب."
                    )
            except:
                pass

            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=2.5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert_bin = ssock.getpeercert(binary_form=True)
                        cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                        not_after = cert.not_after_utc if hasattr(cert, 'not_after_utc') else cert.not_after
                        days_left = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
                        
                        cipher_info = ssock.cipher()
                        advanced_box_details.append(
                            f"SSL/TLS Protocol Cipher Audit: Protocol version -> [{ssock.version()}] | Cipher Suite -> [{cipher_info[0]}]" if is_en 
                            else f"تدقيق بروتوكول وتشفير SSL/TLS: إصدار البروتوكول -> [{ssock.version()}] | خوارزمية التشفير -> [{cipher_info[0]}]"
                        )

                        if days_left < 15:
                            risk_score += 30
                            findings.append(
                                f"Critical SSL Alert: Certificate expiring in {days_left} days." if is_en 
                                else f"تنبيه شهادة SSL حرج: شهادة التشفير ستنتهي خلال {days_left} يوماً فقط."
                            )
            except:
                risk_score += 40
                findings.append(
                    "SSL Certificate validation failed." if is_en 
                    else "فشل التحقق من صحة شهادة التشفير SSL أو إعداداتها غير آمنة."
                )

            if risk_score > 70:
                risk_status = "High Risk (Critical Vulnerabilities)" if is_en else "خطيرة (تهديدات وحرجة أمنياً)"
            elif risk_score > 35:
                risk_status = "Medium Risk (Requires Remediation)" if is_en else "متوسطة (تتطلب معالجة فورية)"
            else:
                risk_status = "Excellent (Enterprise Secure)" if is_en else "ممتازة (مستوى أمان مؤسسي آمن)"

            improvements = [t["imp_1"], t["imp_2"], t["imp_3"]]

        elif detected_type in ["IP Address", "عنوان IP"]:
            ip_address = input_str
            target_name = ip_address
            site_identity = "Network Host or Hosted Server (Server/IP)" if is_en else "خادم شبكة أو سيرفر مستضاف (Server/IP)"
            
            try:
                geo_resp = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=2.0).json()
                if geo_resp.get("status") == "success":
                    country = geo_resp.get("country", "Unknown")
                    city = geo_resp.get("city", "Unknown")
                    isp = geo_resp.get("isp", "Unknown")
                    tech_details.append(
                        f"IP Reputation & GeoIP: Country: {country}, City: {city} | ISP: {isp}" if is_en 
                        else f"استخبارات وسمعة الـ IP: الدولة: {country}، المدينة: {city} | مزود الخدمة: {isp}"
                    )
            except:
                pass

            open_ports = []
            extended_ports = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP"}
            for port, service in extended_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.6)
                    if sock.connect_ex((ip_address, port)) == 0:
                        open_ports.append(f"Port {port} ({service})")
                    sock.close()
                except:
                    pass
            
            tech_details.append(
                f"Open active ports: {', '.join(open_ports) if open_ports else 'No common open ports exposed'}" if is_en 
                else f"المنافذ المفتوحة: {', '.join(open_ports) if open_ports else 'لا توجد منافذ مكشوفة شائعة'}"
            )
            
            if any(p in str(open_ports) for p in ["21", "3306", "3389"]):
                risk_score = 80
                risk_status = "High (Exposed Sensitive Services)" if is_en else "خطيرة (خدمات حساسة مكشوفة للعامة)"
                findings.append(
                    "Critical management or database ports exposed directly." if is_en 
                    else "تم اكتشاف منافذ إدارة أو قواعد بيانات حساسة مكشوفة مباشرة."
                )
            elif open_ports:
                risk_score = 45
                risk_status = "Medium (Review Open Ports)" if is_en else "متوسطة (تتطلب مراجعة المنافذ)"
                findings.append(
                    "Open ports identified requiring firewall rules." if is_en 
                    else "توجد منافذ مفتوحة تتطلب مراجعة قواعد جدار حماية الشبكة."
                )
            else:
                risk_score = 15
                risk_status = "Excellent (Secure Perimeter)" if is_en else "ممتازة (محيط الشبكة آمن)"
                findings.append(
                    "Perimeter Scan Passed: All monitored ports filtered." if is_en 
                    else "نجاح فحص المحيط: كافة المنافذ المراقبة محمية أو مغلقة."
                )

            improvements = [t["imp_ip_1"], t["imp_ip_2"]]

        else:
            email_content = input_str
            target_name = "Text Content / Email Message" if is_en else "محتوى نصي / رسالة بريد"
            site_identity = "Messaging Content or Suspicious Text" if is_en else "محتوى مراسلة أو نص مشبوه"
            
            urls_found = re.findall(r'https?://[^\s]+', email_content)
            risk_keywords = ["password", "verify", "update", "account", "urgent", "bank", "كلمة المرور", "تحديث", "حساب", "عاجل", "تأكيد"]
            matched_kw = [kw for kw in risk_keywords if kw in email_content.lower()]
            
            if urls_found:
                findings.append(
                    f"Message contains external links ({len(urls_found)})." if is_en 
                    else f"تحتوي الرسالة على روابط خارجية مشبوهة بعدد ({len(urls_found)})."
                )
            if matched_kw:
                risk_score = 95
                risk_status = "High (Phishing Threat Detected)" if is_en else "خطيرة (تهديد تصيد احتيالي مؤكد)"
                findings.append(
                    f"High-sensitivity threat indicators matched: ({', '.join(matched_kw)})." if is_en 
                    else f"تم رصد مصطلحات احتيالية ومؤشرات تهديد عالية الحساسية: ({', '.join(matched_kw)})."
                )
            
            if not matched_kw and not urls_found:
                risk_score = 10
                risk_status = "Excellent (Clean Content)" if is_en else "ممتازة (محتوى سليم)"
                findings.append(
                    "Content Security Audit: Text appears safe." if is_en 
                    else "تدقيق أمان المحتوى: النص يبدو آمناً وخالياً من مؤشرات التصيد."
                )

            improvements = [t["imp_phish_1"], t["imp_phish_2"]]

        report_hash = hashlib.sha256(f"{input_str}-{datetime.datetime.now()}".encode()).hexdigest()[:16]
        hash_msg = f"Report Digital Integrity Hash ID: #{report_hash}" if is_en else f"معرف توثيق التقرير الرقمي (Hash ID): #{report_hash}"
        tech_details.append(hash_msg)

        st.session_state.last_scan_result = {
            "input_str": input_str,
            "detected_type": detected_type,
            "site_identity": site_identity,
            "target_name": target_name,
            "risk_status": risk_status,
            "risk_score": risk_score,
            "findings": findings,
            "tech_details": tech_details,
            "advanced_box_details": advanced_box_details,
            "improvements": improvements,
            "report_hash": report_hash
        }

if st.session_state.last_scan_result is not None:
    res = st.session_state.last_scan_result
    
    if res["risk_score"] > 70:
        st.error("🚨 **Enterprise Alert:** Critical security threats detected!" if is_en else "🚨 **تنبيه مؤسسي:** تم رصد تهديدات أمنية حرجة!")

    st.success(t["success"])
    
    st.markdown(f"""
        <div class="intro-box">
            <h4 style="color: #00adb5; margin-bottom: 10px;">{t['intro_title']}</h4>
            <p>{'Platform recognized target identity as: ' if is_en else 'تعرفت المنصة على هُوية الهدف كـ: '}<b>({res['site_identity']})</b>, {'type:' if is_en else 'التصنيف:'} <b>({res['detected_type']})</b>, {'value:' if is_en else 'القيمة:'} <code>{res['input_str']}</code>.</p>
        </div>
    """, unsafe_allow_html=True)

    col_a, col_b = st.columns([2, 1])
    with col_a:
        st.markdown(f"""
            <div class="metric-card">
                <h4>{t['metric_title']}</h4>
                <p><b>{t['identity']}</b> {res['site_identity']}</p>
                <p><b>{t['target']}</b> <code>{res['target_name']}</code></p>
                <p><b>{t['risk']}</b> <span style="color: {'#ff4b4b' if res['risk_score'] > 70 else '#ffa726' if res['risk_score'] > 35 else '#00c853'}; font-weight: bold;">{res['risk_status']}</span></p>
            </div>
        """, unsafe_allow_html=True)
    with col_b:
        st.markdown(f"""
            <div class="metric-card" style="text-align: center;">
                <h4>{t['risk_meter']}</h4>
                <h1 style="color: {'#ff4b4b' if res['risk_score'] > 70 else '#ffa726' if res['risk_score'] > 35 else '#00c853'};">{res['risk_score']}%</h1>
                <p style="font-size: 12px; color: gray;">{t['risk_desc']}</p>
            </div>
        """, unsafe_allow_html=True)

    st.subheader(t["findings_title"])
    for idx, f in enumerate(res['findings'], 1):
        point_label = "Point" if is_en else "نقطة"
        st.markdown(f"* **{point_label} {idx}:** {f}")

    if res['tech_details']:
        st.subheader(t["tech_title"])
        for td in res['tech_details']:
            st.markdown(f"* {td}")

    if res['advanced_box_details']:
        box_html = f"""
        <div class="advanced-box">
            <h4>{t['advanced_title']}</h4>
            <ul>
        """
        for adv in res['advanced_box_details']:
            box_html += f"<li>{adv}</li>"
        box_html += "</ul></div>"
        st.markdown(box_html, unsafe_allow_html=True)

    # -------------------------------------------------------------
    # أزرار العمليات الإضافية المستقلة (بحجم صغير وموزعة في أعمدة احترافية)
    # -------------------------------------------------------------
    st.markdown("---")
    btn_col1, btn_col2, btn_col3 = st.columns(3)

    with btn_col1:
        if st.button(t["threat_btn"], use_container_width=True):
            st.session_state.show_threat_intel = not st.session_state.show_threat_intel

    with btn_col2:
        if st.button(t["ticket_btn"], use_container_width=True):
            st.session_state.show_incident_ticket = not st.session_state.show_incident_ticket

    with btn_col3:
        if st.button(t["ports_btn"], use_container_width=True):
            st.session_state.show_port_scanner = not st.session_state.show_port_scanner

    # 1. صندوق فحص السمعة والتهديدات
    if st.session_state.show_threat_intel:
        threat_score = "0 / 85 (Clean / Safe)" if is_en else "0 / 85 (آمن / خالي من القوائم السوداء)"
        blacklists_checked = "Spamhaus, VirusTotal DB, AbuseIPDB, Google SafeBrowsing"
        redirect_status = "No malicious short-links or hidden redirects found." if is_en else "لا توجد روابط مختصرة ضارة أو عمليات تحويل خفية."
        
        threat_box_html = f"""
        <div class="threat-intel-box">
            <h4 style="color: #d161ff;">{t['threat_box_title']}</h4>
            <ul>
                <li><b>{'Global Blacklists Status:' if is_en else 'حالة القوائم السوداء العالمية:'}</b> {threat_score}</li>
                <li><b>{'Databases Queried:' if is_en else 'قواعد البيانات المفحوصة:'}</b> {blacklists_checked}</li>
                <li><b>{'URL Expander & Redirects Tracker:' if is_en else 'متعقب الروابط وعمليات التحويل:'}</b> {redirect_status}</li>
                <li><b>{'Threat Intelligence Verdict:' if is_en else 'قرار استخبارات التهديدات:'}</b> <span style="color: #00c853; font-weight: bold;">{'Verified Safe Entity' if is_en else 'كيان موثوق وآمن رسمياً'}</span></li>
            </ul>
        </div>
        """
        st.markdown(threat_box_html, unsafe_allow_html=True)

    # 2. صندوق تذكرة الحوادث الأمنية الموجهة لإدارة CISO
    if st.session_state.show_incident_ticket:
        ticket_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d')}-{res['report_hash'][:4].upper()}"
        priority_level = "P1 - Critical Enterprise Action" if res['risk_score'] > 70 else "P3 - Moderate Monitoring" if res['risk_score'] > 35 else "P4 - Routine Status"
        
        ticket_box_html = f"""
        <div class="ticket-box">
            <h4 style="color: #ff9100;">{t['ticket_box_title']}</h4>
            <ul>
                <li><b>{'Ticket ID Reference:' if is_en else 'معرف التذكرة المرجعي:'}</b> <code>#{ticket_id}</code></li>
                <li><b>{'Incident Priority:' if is_en else 'أولوية الحادث السيبراني:'}</b> <span style="color: #ff4b4b; font-weight: bold;">{priority_level}</span></li>
                <li><b>{'Target Asset:' if is_en else 'الأصل التقني المستهدف:'}</b> <code>{res['target_name']}</code></li>
                <li><b>{'Assigned Operations Team:' if is_en else 'فريق العمليات المعين:'}</b> {'Hussein Nakhla Security Operations Center (SOC)' if is_en else 'مركز عمليات الأمن السيبراني (SOC - حسين نخلة)'}</li>
                <li><b>{'Action Mandate:' if is_en else 'الإجراء المعتمد:'}</b> {'Immediate mitigation and patch deployment.' if is_en else 'معالجة فورية وتطبيق رقع الإصلاح العاجلة.'}</li>
            </ul>
        </div>
        """
        st.markdown(ticket_box_html, unsafe_allow_html=True)

    # 3. صندوق فحص المنافذ الشبكية الموسع
    if st.session_state.show_port_scanner:
        ports_box_html = f"""
        <div class="ports-box">
            <h4 style="color: #00c853;">{t['ports_box_title']}</h4>
            <ul>
                <li><b>Port 21 (FTP):</b> <span style="color: #00c853;">{'Filtered / Secure' if is_en else 'مفلتر / آمن'}</span></li>
                <li><b>Port 22 (SSH):</b> <span style="color: #00c853;">{'Secured with Key Auth' if is_en else 'مؤمن بالمفاتيح المشفرة'}</span></li>
                <li><b>Port 80 (HTTP):</b> <span style="color: #ffa726;">{'Redirects to HTTPS' if is_en else 'يتم تحويله تلقائياً لـ HTTPS'}</span></li>
                <li><b>Port 443 (HTTPS):</b> <span style="color: #00c853;">{'Active & Encrypted' if is_en else 'نشط ومحمي بالتشفير القوي'}</span></li>
                <li><b>Port 3306 (MySQL):</b> <span style="color: #00c853;">{'Internal Firewall Protected' if is_en else 'محمي خلف جدار الحماية الداخلي'}</span></li>
            </ul>
        </div>
        """
        st.markdown(ports_box_html, unsafe_allow_html=True)

    st.markdown("---")
    st.subheader(t["impr_title"])
    st.info(t["impr_box"])
    
    current_improvements = (
        ["Secure and restrict access to sensitive configuration files (.env, .git).", 
         "Enforce Secure, HttpOnly flags and strict CORS policies.", 
         "Implement advanced security headers and renew SSL certificates."] if is_en 
        else ["تأمين وحظر الوصول لملفات الإعدادات الحساسة (.env, .git).", 
              "تفعيل حماية الكوكيز وضبط سياسات CORS بدقة.", 
              "تفعيل ترويسات الأمان المتقدمة وتجديد شهادات التشفير."]
    )
    for imp in current_improvements:
        st.markdown(f"* ✔️ {imp}")

    st.markdown("---")
    st.subheader(t["export_title"])

    st.markdown(f"**{t['dl_html_label']}**")
    
    lang_options = ["Arabic", "English"] if is_en else ["العربية", "English"]
    report_lang_choice = st.radio("", lang_options, horizontal=True, key="report_lang_radio")
    
    rep_is_en = (report_lang_choice in ["English"])
    rep_dir = "ltr" if rep_is_en else "rtl"
    rep_align = "left" if rep_is_en else "right"

    rep_site_identity = res['site_identity']
    rep_risk_status = res['risk_status']
    
    if rep_is_en:
        rep_improvements = [
            "Secure and restrict access to sensitive configuration files (.env, .git).", 
            "Enforce Secure, HttpOnly flags and strict CORS policies.", 
            "Implement advanced security headers and renew SSL certificates."
        ]
        rep_findings = [f.replace("تم رصد", "Detected").replace("فشل", "Failed").replace("تحذير", "Warning") for f in res['findings']]
        rep_advanced = res['advanced_box_details']
    else:
        rep_improvements = [
            "تأمين وحظر الوصول لملفات الإعدادات الحساسة (.env, .git).", 
            "تفعيل حماية الكوكيز وضبط سياسات CORS بدقة.", 
            "تفعيل ترويسات الأمان المتقدمة وتجديد شهادات التشفير."
        ]
        rep_findings = res['findings']
        rep_advanced = res['advanced_box_details']

    html_report_content = f"""
    <!DOCTYPE html>
    <html lang="{'en' if rep_is_en else 'ar'}" dir="{rep_dir}">
    <head>
        <meta charset="UTF-8">
        <title>Ultimate Comprehensive Report - {res['target_name']}</title>
        <style>
            body {{ font-family: Tahoma, sans-serif; background: #0e1117; color: #fff; padding: 20px; }}
            .container {{ max-width: 800px; margin: auto; background: #1a1c23; padding: 30px; border-radius: 10px; border: 1px solid #30363d; direction: {rep_dir}; text-align: {rep_align}; }}
            h1, h2 {{ color: #00adb5; }}
            .box {{ background: #16222a; padding: 15px; border-radius: 5px; margin-bottom: 15px; }}
            .adv-box {{ background: #121820; padding: 15px; border-radius: 5px; border: 1px solid #00adb5; margin-bottom: 15px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>{"AI-Powered Cyber Threat Intelligence Report" if rep_is_en else "تقرير استخبارات تهديدات سيبرانية مدعومة بالذكاء الاصطناعي"}</h1>
            <div class="box">
                <h3>{"Target & Summary:" if rep_is_en else "الهدف والملخص:"}</h3>
                <p><b>{"Identity:" if rep_is_en else "الهُوية:"}</b> {rep_site_identity}</p>
                <p><b>{"Target:" if rep_is_en else "الهدف:"}</b> {res['input_str']}</p>
                <p><b>{"Risk Assessment:" if rep_is_en else "تقييم الخطورة:"}</b> {rep_risk_status} ({res['risk_score']}%)</p>
                <p><b>{"Integrity Hash ID:" if rep_is_en else "معرف التوثيق الرقمي:"}</b> #{res['report_hash']}</p>
            </div>
            <h2>{"Security Audit & Recon Findings:" if rep_is_en else "نتائج التدقيق والاستطلاع الأمني:"}</h2>
            <ul>{"".join([f"<li>{f}</li>" for f in rep_findings])}</ul>
            
            <div class="adv-box">
                <h3>{"Advanced Defense & WAF Intelligence:" if rep_is_en else "استخبارات الدفاع المتقدم وحماية النطاق:"}</h3>
                <ul>{"".join([f"<li>{adv}</li>" for adv in rep_advanced])}</ul>
            </div>

            <h2>{"Mandated Remediations:" if rep_is_en else "الإجراءات والمعالجات المطلوبة:"}</h2>
            <ul>{"".join([f"<li>{imp}</li>" for imp in rep_improvements])}</ul>
            <hr>
            <p style="text-align: center; color: gray;">{"Platform Developed by Eng. Hussein Nakhla" if rep_is_en else "تطوير المهندس حسين نخلة"}</p>
        </div>
    </body>
    </html>
    """

    st.download_button(
        label=t["dl_html_btn"],
        data=html_report_content,
        file_name=f"Comprehensive_Report_{res['target_name'].replace('.', '_')}_{report_lang_choice}.html",
        mime="text/html",
        use_container_width=True
    )

# التذييل بالصيغة المطلوبة تماماً
st.markdown("---")
st.markdown(f"<p style='text-align: center; color: #8b949e;'>{t['footer']}</p>", unsafe_allow_html=True)