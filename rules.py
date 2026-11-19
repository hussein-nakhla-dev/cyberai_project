"""Finding catalogue: metadata, CVSS vectors and bilingual text per rule.

Scanners only decide *whether* a rule fires and attach evidence; everything
else (CWE, CVSS vector, titles, remediation) lives here.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass

from .cvss import base_score, severity_from_score
from .models import Finding
from .utils import now_utc


def V(metrics: str) -> str:
    return "CVSS:3.1/" + metrics


@dataclass(frozen=True)
class Rule:
    cwe: str | None
    category: str
    vector: str | None
    title: dict[str, str]
    fix: dict[str, str]


def R(cwe, category, vector, t_ar, t_en, f_ar, f_en) -> Rule:
    return Rule(cwe, category, vector, {"ar": t_ar, "en": t_en}, {"ar": f_ar, "en": f_en})


RULES: dict[str, Rule] = {
    # ---- HTTP security headers -------------------------------------------
    "HDR-HSTS": R(
        "CWE-319", "transport", V("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
        "غياب ترويسة Strict-Transport-Security (HSTS)",
        "Missing Strict-Transport-Security (HSTS) header",
        "أرسل Strict-Transport-Security بقيمة max-age=31536000; includeSubDomains بعد التأكد من أن جميع النطاقات الفرعية تعمل عبر HTTPS.",
        "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once every subdomain is served over HTTPS.",
    ),
    "HDR-CSP": R(
        "CWE-693", "misconfig", V("AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        "غياب سياسة أمان المحتوى (Content-Security-Policy)",
        "Missing Content-Security-Policy header",
        "عرّف سياسة CSP صارمة تحدّ مصادر السكربتات والأنماط (ابدأ بوضع Report-Only ثم شدّد تدريجياً).",
        "Define a strict CSP that restricts script and style sources (start in Report-Only mode, then tighten).",
    ),
    "HDR-XCTO": R(
        "CWE-693", "misconfig", V("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
        "غياب ترويسة X-Content-Type-Options",
        "Missing X-Content-Type-Options header",
        "أضف X-Content-Type-Options: nosniff لمنع المتصفح من تخمين نوع المحتوى.",
        "Add X-Content-Type-Options: nosniff to stop browsers from MIME-sniffing responses.",
    ),
    "HDR-XFO": R(
        "CWE-1021", "misconfig", V("AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
        "غياب الحماية من النقر الخفي (X-Frame-Options / frame-ancestors)",
        "No clickjacking protection (X-Frame-Options / frame-ancestors)",
        "أضف X-Frame-Options: DENY أو التوجيه frame-ancestors 'none' ضمن CSP.",
        "Add X-Frame-Options: DENY or the CSP directive frame-ancestors 'none'.",
    ),
    "HDR-REFERRER": R(
        "CWE-200", "misconfig", V("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
        "غياب ترويسة Referrer-Policy",
        "Missing Referrer-Policy header",
        "أضف Referrer-Policy: strict-origin-when-cross-origin أو سياسة أشد.",
        "Add Referrer-Policy: strict-origin-when-cross-origin or stricter.",
    ),
    "HDR-PERMISSIONS": R(
        "CWE-693", "misconfig", None,
        "غياب ترويسة Permissions-Policy",
        "Missing Permissions-Policy header",
        "حدّد صلاحيات المتصفح المسموحة (الكاميرا، الموقع…) عبر Permissions-Policy.",
        "Restrict browser features (camera, geolocation, ...) with Permissions-Policy.",
    ),
    "COOKIE-FLAGS": R(
        "CWE-614", "misconfig", V("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
        "ملفات تعريف ارتباط تفتقد إلى سمات الأمان",
        "Cookies missing security attributes",
        "أضف السمات Secure وHttpOnly وSameSite لملفات تعريف الارتباط الحسّاسة، وخصوصاً ملفات الجلسات.",
        "Set Secure, HttpOnly and SameSite on sensitive cookies, especially session cookies.",
    ),
    "INFO-BANNER": R(
        "CWE-200", "disclosure", V("AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
        "كشف اسم الخادم أو إصداره في الترويسات",
        "Server software or version disclosed in headers",
        "أخفِ أرقام الإصدارات من الترويستين Server وX-Powered-By لتقليل المعلومات المتاحة للمهاجم.",
        "Remove version numbers from the Server and X-Powered-By headers to reduce attacker intelligence.",
    ),
    "TRANSPORT-NOHTTPS": R(
        "CWE-319", "transport", V("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N"),
        "الموقع يخدم المحتوى عبر HTTP دون إعادة توجيه إلى HTTPS",
        "Site serves content over HTTP without redirecting to HTTPS",
        "فعّل إعادة توجيه دائمة (301) من HTTP إلى HTTPS ثم فعّل HSTS.",
        "Enable a permanent (301) redirect from HTTP to HTTPS, then enable HSTS.",
    ),
    # ---- Exposed files ---------------------------------------------------
    "EXPOSE-ENV": R(
        "CWE-538", "disclosure", V("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
        "ملف إعدادات البيئة (.env) متاح للعموم",
        "Environment file (.env) is publicly accessible",
        "احجب الوصول إلى الملفات المخفية فوراً، وأدِر (Rotate) جميع الأسرار والمفاتيح الواردة فيه، وأبقِه خارج جذر الويب.",
        "Block dotfiles immediately, rotate every secret it contains and keep it outside the web root.",
    ),
    "EXPOSE-GIT": R(
        "CWE-527", "disclosure", V("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "مستودع Git مكشوف (/.git)",
        "Git repository exposed (/.git)",
        "احجب المسار /.git على الخادم، وأزل المستودع من جذر الويب، وأدِر أي أسرار قد تكون في سجل الإيداعات.",
        "Block /.git on the server, remove the repository from the web root and rotate any secrets in its history.",
    ),
    # ---- TLS -------------------------------------------------------------
    "TLS-INVALID": R(
        "CWE-295", "crypto", V("AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"),
        "شهادة TLS لم تجتز التحقق",
        "TLS certificate failed validation",
        "ثبّت شهادة صالحة من جهة موثوقة تغطي اسم النطاق وتتضمن السلسلة الكاملة، وفعّل التجديد الآلي.",
        "Install a valid certificate from a trusted CA that covers the hostname and the full chain, and enable auto-renewal.",
    ),
    "TLS-EXPIRING": R(
        "CWE-298", "crypto", V("AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"),
        "شهادة TLS تنتهي قريباً ({days_remaining} يوماً)",
        "TLS certificate expires soon ({days_remaining} days)",
        "جدّد الشهادة قبل انتهائها وفعّل التجديد الآلي (مثل ACME).",
        "Renew the certificate before it expires and enable automatic renewal (e.g. ACME).",
    ),
    "TLS-LEGACY": R(
        "CWE-326", "crypto", V("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "بروتوكول TLS قديم قيد الاستخدام ({version})",
        "Legacy TLS protocol in use ({version})",
        "عطّل SSLv3 وTLS 1.0 وTLS 1.1 وأبقِ TLS 1.2 وما فوق.",
        "Disable SSLv3, TLS 1.0 and TLS 1.1; keep TLS 1.2 and above.",
    ),
    "TLS-WEAKKEY": R(
        "CWE-326", "crypto", V("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "مفتاح الشهادة ضعيف ({key})",
        "Weak certificate key ({key})",
        "أصدر شهادة جديدة بمفتاح RSA بطول 2048 بت أو أكثر أو منحنى ECDSA حديث.",
        "Issue a new certificate with an RSA key of 2048+ bits or a modern ECDSA curve.",
    ),
    # ---- DNS / email authentication -------------------------------------
    "DNS-SPF-MISSING": R(
        "CWE-290", "email_auth", V("AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"),
        "لا يوجد سجل SPF للنطاق",
        "No SPF record published for the domain",
        "انشر سجل SPF يحدد خوادم الإرسال المسموحة، أو v=spf1 -all للنطاقات التي لا ترسل بريداً.",
        "Publish an SPF record listing authorized senders, or v=spf1 -all for domains that never send mail.",
    ),
    "DNS-SPF-WEAK": R(
        "CWE-290", "email_auth", V("AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"),
        "سجل SPF ضعيف (يسمح بأي مُرسِل)",
        "Weak SPF record (allows any sender)",
        "استبدل +all أو ?all بـ -all أو ~all بعد حصر المرسلين المصرّح لهم.",
        "Replace +all / ?all with -all or ~all after enumerating authorized senders.",
    ),
    "DNS-DMARC-MISSING": R(
        "CWE-290", "email_auth", V("AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"),
        "لا يوجد سجل DMARC للنطاق",
        "No DMARC record published for the domain",
        "انشر DMARC تدريجياً: ابدأ بـ p=none مع تقارير، ثم quarantine ثم reject.",
        "Roll out DMARC gradually: p=none with reporting, then quarantine, then reject.",
    ),
    "DNS-DMARC-WEAK": R(
        "CWE-290", "email_auth", V("AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"),
        "سياسة DMARC غير مُلزِمة (p=none)",
        "DMARC policy is not enforcing (p=none)",
        "بعد مراجعة التقارير ارفع السياسة إلى quarantine ثم reject.",
        "After reviewing reports, raise the policy to quarantine and then reject.",
    ),
    "DNS-MX-MISSING": R(
        None, "dns", None,
        "النطاق بلا سجلات MX (لا يستقبل بريداً)",
        "Domain has no MX records (cannot receive email)",
        "إن كان النطاق يجب أن يستقبل بريداً فأضف سجلات MX صحيحة، وإلا فانشر SPF بصيغة -all.",
        "If the domain should receive email add valid MX records; otherwise publish SPF -all.",
    ),
    "DNS-CAA-MISSING": R(
        None, "dns", None,
        "لا يوجد سجل CAA",
        "No CAA record",
        "أضف سجل CAA لحصر الجهات المسموح لها بإصدار شهادات النطاق.",
        "Add a CAA record to restrict which CAs may issue certificates for the domain.",
    ),
    # ---- Network exposure ------------------------------------------------
    "PORT-RISKY": R(
        "CWE-284", "exposure", V("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "خدمة حسّاسة متاحة من الإنترنت: {service} (المنفذ {port})",
        "Sensitive service reachable from the internet: {service} (port {port})",
        "قيّد الوصول إلى الخدمة بجدار ناري أو VPN، وتأكد من تفعيل المصادقة والتشفير، أو أغلق المنفذ.",
        "Restrict the service behind a firewall or VPN, enforce authentication and encryption, or close the port.",
    ),
    # ---- Threat intelligence --------------------------------------------
    "INTEL-VT": R(
        None, "reputation", V("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L"),
        "محركات في VirusTotal تصنّف الهدف كخبيث أو مشبوه",
        "VirusTotal engines flag the target as malicious or suspicious",
        "راجع تقرير VirusTotal وتحقق من اختراق محتمل أو محتوى ضار، ثم اطلب إعادة التقييم بعد المعالجة.",
        "Review the VirusTotal report, check for compromise or malicious content and request re-analysis after cleanup.",
    ),
    "INTEL-ABUSE": R(
        None, "reputation", V("AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L"),
        "سمعة سيئة في AbuseIPDB (نسبة الإساءة {score}%)",
        "Poor reputation in AbuseIPDB (abuse confidence {score}%)",
        "افحص نشاط العنوان وتحقق من إساءة الاستخدام أو الاختراق، وانظر في حظره أو معالجته.",
        "Investigate the address for abuse or compromise and consider blocking or remediating it.",
    ),
    "INTEL-CVE": R(
        "CWE-1104", "component", V("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        "ثغرات معروفة مرتبطة بالخدمات المكشوفة ({count})",
        "Known CVEs associated with exposed services ({count})",
        "تحقق من الإصدارات الفعلية للخدمات المكشوفة وطبّق التحديثات؛ القائمة مستنتجة من بصمات خارجية وقد تتضمن إيجابيات كاذبة.",
        "Verify the real versions of exposed services and patch; the list is inferred from external fingerprints and may contain false positives.",
    ),
}


def make_finding(
    rule_id: str,
    host: str,
    scanner: str,
    evidence: dict,
    *,
    status: str = "Verified",
    confidence: float = 0.9,
    key: str = "",
    timestamp: str | None = None,
) -> Finding:
    rule = RULES[rule_id]
    score = base_score(rule.vector) if rule.vector else 0.0
    digest = hashlib.sha1(f"{rule_id}|{host}|{key}".encode()).hexdigest()[:6]
    return Finding(
        finding_id=f"EVAS-{rule_id}-{digest}",
        rule_id=rule_id,
        category=rule.category,
        cwe=rule.cwe,
        severity=severity_from_score(score),
        cvss_score=score,
        cvss_vector=rule.vector,
        status=status if score > 0 else "Informational",
        confidence=confidence,
        scanner=scanner,
        evidence=evidence,
        timestamp=timestamp or now_utc().isoformat(timespec="seconds"),
    )


def _fmt(template: str, evidence: dict) -> str:
    return template.format_map(defaultdict(str, {k: v for k, v in evidence.items()}))


def title_of(finding: Finding, lang: str) -> str:
    return _fmt(RULES[finding.rule_id].title["ar" if lang == "ar" else "en"], finding.evidence)


def fix_of(finding: Finding, lang: str) -> str:
    return _fmt(RULES[finding.rule_id].fix["ar" if lang == "ar" else "en"], finding.evidence)
