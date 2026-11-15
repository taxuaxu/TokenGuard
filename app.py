"""TokenGuard control panel (Streamlit).

A visual dashboard to run and watch every part of TokenGuard, with an in-app
Turkish/English language switch and explanatory text throughout:
  * Overview with a one-click "run all" summary
  * Static analysis of a pasted JWT, with severity badges and an ordered chart
  * Active testing against the local vulnerable server (endpoint x attack matrix)
  * The OAuth 2.1 MCP case study (secure vs misconfigured)
  * Evaluation scores (precision/recall/F1) and the jwt_tool baseline

Run:  streamlit run app.py
"""
from __future__ import annotations

import html
import json
import subprocess
import sys
import time
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from tokenguard import AnalysisConfig, analyze
from tokenguard.parser import TokenParseError, parse_token
from tokenguard.rules import ALL_GROUPS
from tokenguard.report import (REMEDIATION, claim_timeline, relative_phrase, risk_level,
                               to_markdown)

ROOT = Path(__file__).resolve().parent

SEV_COLOR = {"CRITICAL": "#e03131", "HIGH": "#f26d4e", "MEDIUM": "#e0a800",
             "LOW": "#4dabf7", "INFO": "#868e96"}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

GREEN, RED, AMBER, GREY = "#2b8a5a", "#c92a2a", "#b8860b", "#343a46"

SAMPLE_NONE = ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
               "eyJzdWIiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9.")

# Lab servers the panel can launch. key -> (command, base, health path)
SERVERS = {
    "vuln": ([sys.executable, str(ROOT / "vuln_server" / "app.py")],
             "http://127.0.0.1:5000", "/endpoints"),
    "mcp_secure": ([sys.executable, str(ROOT / "mcp_server" / "server.py"), "--port", "7000"],
                   "http://127.0.0.1:7000", "/.well-known/oauth-protected-resource"),
    "mcp_insecure": ([sys.executable, str(ROOT / "mcp_server" / "server.py"),
                      "--insecure", "--port", "7001"],
                     "http://127.0.0.1:7001", "/.well-known/oauth-protected-resource"),
}

# ----------------------------------------------------------------- translations

STR = {
    "subtitle": {"tr": "JWT Güvenlik Analizi — Kontrol Paneli",
                 "en": "JWT Security Analysis — Control Panel"},
    # sidebar
    "sidebar_servers": {"tr": "Lab sunucuları", "en": "Lab servers"},
    "running": {"tr": "çalışıyor", "en": "running"},
    "stopped": {"tr": "durduruldu", "en": "stopped"},
    "start": {"tr": "Başlat", "en": "Start"},
    "stop": {"tr": "Durdur", "en": "Stop"},
    "servers_caption": {"tr": "Sunucular yalnızca 127.0.0.1 üzerinde, yerel test için çalışır.",
                        "en": "Servers run only on 127.0.0.1 for local testing."},
    "srv_vuln": {"tr": "Zafiyetli sunucu :5000", "en": "Vulnerable server :5000"},
    "srv_mcp_secure": {"tr": "MCP güvenli :7000", "en": "MCP secure :7000"},
    "srv_mcp_insecure": {"tr": "MCP hatalı yapılandırılmış :7001",
                         "en": "MCP misconfigured :7001"},
    # tabs
    "tab_overview": {"tr": "Genel Bakış", "en": "Overview"},
    "tab_static": {"tr": "Statik Analiz", "en": "Static analysis"},
    "tab_active": {"tr": "Aktif Test", "en": "Active testing"},
    "tab_mcp": {"tr": "MCP Vaka Çalışması", "en": "MCP case study"},
    "tab_eval": {"tr": "Değerlendirme", "en": "Evaluation"},
    # overview
    "ov_intro": {
        "tr": "Bu panodan TokenGuard'ın tüm parçalarını çalıştırıp sonuçları görebilirsin. "
              "Soldaki menüden lab sunucularını başlat/durdur; aşağıdaki **Tüm testleri "
              "çalıştır** düğmesi açık olan sunuculara karşı her şeyi tek tıkla çalıştırır.",
        "en": "This panel runs and shows every part of TokenGuard. Start/stop the lab "
              "servers in the sidebar; the **Run all tests** button below runs everything "
              "against whichever servers are up, in one click."},
    "ov_server_status": {"tr": "Lab sunucu durumu", "en": "Lab server status"},
    "ov_summary": {"tr": "Tek tıkla özet", "en": "One-click summary"},
    "ov_summary_caption": {
        "tr": "Açık olan lab sunucularına karşı aktif testleri, iki MCP probe'unu ve "
              "değerlendirmeyi çalıştırıp sonuçları özetler.",
        "en": "Runs active tests, both MCP probes, and the evaluation against whichever "
              "lab servers are up, then summarizes the results."},
    "ov_run_all": {"tr": "▶  Tüm testleri çalıştır", "en": "▶  Run all tests"},
    "ov_spinner": {"tr": "Tüm testler çalışıyor...", "en": "Running all tests..."},
    "ov_last_run": {"tr": "Son çalışma: {ts}", "en": "Last run at {ts}"},
    "m_active_flaws": {"tr": "Bulunan aktif açık", "en": "Active flaws found"},
    "m_mcp_secure": {"tr": "MCP güvenli — açık", "en": "MCP secure vulns"},
    "m_mcp_misconfig": {"tr": "MCP hatalı — açık", "en": "MCP misconfig vulns"},
    "m_recall": {"tr": "Tespit duyarlılığı (all)", "en": "Detection recall (all)"},
    "ov_skipped": {"tr": "Bazı sunucular kapalı olduğu için atlandı: {names}",
                   "en": "Some servers were stopped, so parts were skipped: {names}"},
    "ov_tabs_expander": {"tr": "Her sekme ne işe yarar?", "en": "What each tab does"},
    "ov_tabs_body": {
        "tr": "- **Statik Analiz** — Bir JWT yapıştır; araç imzayı doğrulamadan çözüp "
              "güvenlik kurallarından geçirir ve bulguları önem derecesine göre listeler.\n"
              "- **Aktif Test** — Zafiyetli yerel sunucuya elde üretilmiş saldırı token'ları "
              "gönderir; matris her endpoint'in hangi saldırıyı kabul ettiğini gösterir.\n"
              "- **MCP Vaka Çalışması** — OAuth 2.1 korumalı MCP sunucusunun yetkilendirme "
              "kurallarını (401 challenge, metadata keşfi, audience binding, expiry) dener.\n"
              "- **Değerlendirme** — Etiketli veri kümesinde precision/recall/F1 ve "
              "jwt_tool ile kıyaslama.",
        "en": "- **Static analysis** — paste a JWT; the tool decodes it without trusting the "
              "signature, runs the rules, and lists findings by severity.\n"
              "- **Active testing** — sends crafted tokens to the local vulnerable server; "
              "the matrix shows which attacks each endpoint accepts.\n"
              "- **MCP case study** — probes the OAuth 2.1 MCP server's authorization rules "
              "(401 challenge, metadata discovery, audience binding, expiry).\n"
              "- **Evaluation** — precision/recall/F1 on a labeled dataset and the jwt_tool "
              "baseline."},
    # static
    "st_title": {"tr": "Bir JWT'yi analiz et", "en": "Analyze a JWT"},
    "st_intro": {
        "tr": "JWT'yi yapıştır. Araç onu **imzasını doğrulamadan** çözer (güvensiz token'ları "
              "da incelemek için) ve seçtiğin kural gruplarından geçirir. Bulgular, önem "
              "derecesi · başlık · kural kimliği · etkilenen bölüm ve maskeli kanıt ile gösterilir.",
        "en": "Paste a JWT. The tool decodes it **without verifying the signature** (so it can "
              "inspect insecure tokens) and runs the selected rule groups. Each finding shows "
              "its severity, title, rule id, affected part, and masked evidence."},
    "st_groups": {"tr": "Kural grupları", "en": "Rule groups"},
    "st_groups_help": {
        "tr": "algorithm = imza algoritması sorunları (none/eksik/bilinmeyen/beklenmeyen, "
              "jwk/jku/x5u/kid) · claims = exp/aud/iss, ömür, nbf, hassas veri · "
              "weak_key = wordlist ile zayıf HMAC anahtarı kurtarma.",
        "en": "algorithm = signing-algorithm issues (none/missing/unknown/unexpected, "
              "jwk/jku/x5u/kid) · claims = exp/aud/iss, lifetime, nbf, sensitive data · "
              "weak_key = recover a weak HMAC key from the wordlist."},
    "st_maxlife": {"tr": "Maksimum token ömrü (saat)", "en": "Max token lifetime (hours)"},
    "st_maxlife_help": {
        "tr": "Bu süreden daha uzun ömürlü token'lar 'aşırı ömür' (LONG_LIFETIME) olarak işaretlenir.",
        "en": "Tokens valid longer than this are flagged as excessive lifetime (LONG_LIFETIME)."},
    "st_expected": {"tr": "Beklenen algoritmalar (virgülle, opsiyonel)",
                    "en": "Expected algorithms (comma-separated, optional)"},
    "st_expected_help": {
        "tr": "Uygulamanın kabul ettiği algoritmalar. Örn. 'RS256' girip HS256 token verirsen, "
              "beklenmeyen algoritma (ALG_UNEXPECTED — algoritma karışıklığı) yakalanır.",
        "en": "The algorithms your app accepts. E.g. enter 'RS256' and pass an HS256 token to "
              "catch an unexpected algorithm (ALG_UNEXPECTED — algorithm confusion)."},
    "st_token": {"tr": "Token", "en": "Token"},
    "st_load_sample": {"tr": "Örnek yükle (alg=none)", "en": "Load sample (alg=none)"},
    "st_parse_err": {"tr": "Token çözülemedi: {err}", "en": "Could not parse token: {err}"},
    "st_header": {"tr": "Başlık (header)", "en": "Header"},
    "st_payload": {"tr": "Yük (payload)", "en": "Payload"},
    "st_findings": {"tr": "Bulgular ({n})", "en": "Findings ({n})"},
    "st_no_issues": {"tr": "Sorun bulunamadı.", "en": "No issues found."},
    "st_download_findings": {"tr": "Bulguları indir (JSON)", "en": "Download findings (JSON)"},
    "sev_expander": {"tr": "Önem dereceleri ne anlama gelir?",
                     "en": "What the severity levels mean"},
    "sev_body": {
        "tr": "- **CRITICAL** — Doğrudan sömürülebilir, token sahtekârlığına yol açar "
              "(ör. alg=none, kırılmış zayıf anahtar).\n"
              "- **HIGH** — Ciddi zayıflık (ör. exp yok, gömülü jwk, hassas veri).\n"
              "- **MEDIUM** — Kötüye kullanılabilir yanlış yapılandırma (ör. expired kabulü, "
              "aud yok, kid enjeksiyonu).\n"
              "- **LOW** — Küçük zayıflık (ör. iss yok).\n"
              "- **INFO** — Bilgilendirme (ör. nbf gelecekte).",
        "en": "- **CRITICAL** — directly exploitable, enables token forgery "
              "(e.g. alg=none, a cracked weak key).\n"
              "- **HIGH** — serious weakness (e.g. no exp, embedded jwk, sensitive data).\n"
              "- **MEDIUM** — abusable misconfiguration (e.g. accepting expired, no aud, "
              "kid injection).\n"
              "- **LOW** — minor weakness (e.g. no iss).\n"
              "- **INFO** — informational (e.g. nbf in the future)."},
    # active
    "act_title": {"tr": "Zafiyetli sunucuya karşı aktif test",
                  "en": "Active testing against the vulnerable server"},
    "act_intro": {
        "tr": "Araç, elde üretilmiş saldırı token'larını yerel zafiyetli sunucuya gönderir ve "
              "her endpoint'in hangi saldırıyı kabul/ret ettiğini kaydeder. Yalnızca 127.0.0.1 "
              "hedeflenebilir.",
        "en": "The tool sends crafted attack tokens to the local vulnerable server and records "
              "which attacks each endpoint accepts or rejects. Only 127.0.0.1 may be targeted."},
    "act_server_running": {"tr": "sunucu çalışıyor", "en": "server running"},
    "act_server_stopped": {"tr": "sunucu kapalı — soldaki menüden başlat",
                           "en": "server stopped — start it from the sidebar"},
    "act_target": {"tr": "Hedef (yalnızca localhost)", "en": "Target (localhost only)"},
    "act_secret": {"tr": "Bilinen HMAC sırrı (opsiyonel)", "en": "Known HMAC secret (optional)"},
    "act_secret_help": {
        "tr": "Biliniyorsa, zayıf anahtarla imzalı sahte (forged) token üretip sunucunun kabul "
              "edip etmediğini test etmek için kullanılır.",
        "en": "If known, used to forge a token signed with the weak key and test whether the "
              "server accepts it."},
    "act_run": {"tr": "Aktif testleri çalıştır", "en": "Run active tests"},
    "act_matrix_legend": {
        "tr": "🟥 AÇIK = güvensiz token kabul edildi · 🟩 = doğru davranış (ret/kabul) · "
              "– = atlandı · küçük sayı = HTTP durum kodu · hücrenin üzerine gel → not.",
        "en": "🟥 VULN = insecure token accepted · 🟩 = correct behavior · – = skipped · "
              "small number = HTTP status · hover a cell for its note."},
    "act_flaws_title": {"tr": "Endpoint başına tespit edilen açıklar",
                        "en": "Detected flaws per endpoint"},
    "act_no_flaws": {"tr": "açık tespit edilmedi", "en": "no flaws detected"},
    "act_download": {"tr": "Sonuçları indir (JSON)", "en": "Download results (JSON)"},
    "act_attacks_expander": {"tr": "Saldırı türleri nedir?", "en": "What the attack types mean"},
    "act_attacks_body": {
        "tr": "- **NO TOKEN** — Token olmadan istek; korumalı endpoint reddetmeli.\n"
              "- **BASELINE VALID** — Geçerli token; kabul edilmeli (temel doğrulama).\n"
              "- **ALG NONE** — İmzasız (alg=none) token; reddedilmeli.\n"
              "- **TAMPERED SIGNATURE** — İmzası bozulmuş token; reddedilmeli.\n"
              "- **EXPIRED TOKEN** — Süresi dolmuş token; reddedilmeli.\n"
              "- **WRONG AUDIENCE** — Başka servise ait token; reddedilmeli.\n"
              "- **WEAK KEY FORGERY** — Kırılan zayıf anahtarla imzalanmış sahte token; reddedilmeli.",
        "en": "- **NO TOKEN** — request with no token; a protected endpoint must reject.\n"
              "- **BASELINE VALID** — a valid token; must be accepted (sanity check).\n"
              "- **ALG NONE** — an unsigned (alg=none) token; must be rejected.\n"
              "- **TAMPERED SIGNATURE** — a token with a broken signature; must be rejected.\n"
              "- **EXPIRED TOKEN** — a past-expiry token; must be rejected.\n"
              "- **WRONG AUDIENCE** — a token for another service; must be rejected.\n"
              "- **WEAK KEY FORGERY** — a token forged with the cracked weak key; must be rejected."},
    # mcp
    "mcp_title": {"tr": "OAuth 2.1 MCP sunucu vaka çalışması",
                  "en": "OAuth 2.1 MCP server case study"},
    "mcp_intro": {
        "tr": "MCP yetkilendirme spesifikasyonuna (OAuth 2.1 + RFC 9728) göre yerel MCP "
              "sunucusunu dener: kimliksiz 401 challenge, korumalı-kaynak metadata keşfi, "
              "**audience binding** (başka kaynağa ait token reddedilmeli — confused-deputy) "
              "ve süre (expiry) kontrolü.",
        "en": "Probes the local MCP server per the MCP authorization spec (OAuth 2.1 + "
              "RFC 9728): the unauthenticated 401 challenge, protected-resource metadata "
              "discovery, **audience binding** (a token for another resource must be rejected "
              "— confused-deputy), and expiry."},
    "mcp_target": {"tr": "MCP sunucusu (yalnızca localhost)", "en": "MCP server (localhost only)"},
    "mcp_run": {"tr": "MCP probe çalıştır", "en": "Run MCP probe"},
    "mcp_vulns": {"tr": "Zafiyetler: {v}", "en": "Vulnerabilities: {v}"},
    "mcp_no_vulns": {"tr": "Yetkilendirme zafiyeti tespit edilmedi.",
                     "en": "No authorization vulnerabilities detected."},
    "mcp_checks_expander": {"tr": "Kontroller ne anlama gelir?", "en": "What the checks mean"},
    "mcp_checks_body": {
        "tr": "- **PASS** — Sunucu bu kuralda doğru davrandı.\n"
              "- **FAIL** — Beklenen davranış görülmedi (ama net bir zafiyet etiketi yok).\n"
              "- **Zafiyet etiketi** (ör. AUDIENCE binding) — Sunucu güvenlik kuralını ihlal "
              "ediyor; güvenli varyant hepsini geçer, hatalı varyant audience kontrolünü atlar.",
        "en": "- **PASS** — the server behaved correctly for this rule.\n"
              "- **FAIL** — the expected behavior was not observed (no specific vuln label).\n"
              "- **Vulnerability label** (e.g. AUDIENCE binding) — the server breaks a security "
              "rule; the secure variant passes all, the misconfigured one skips audience checks."},
    # evaluation
    "ev_title": {"tr": "Tespit değerlendirmesi", "en": "Detection evaluation"},
    "ev_intro": {
        "tr": "Etiketli bir veri kümesi üzerinde TokenGuard'ın tespitini ölçer. İki "
              "konfigürasyon karşılaştırılır: **basic** (zayıf-anahtar tespiti hariç) ve "
              "**all** (dahil). İsteğe bağlı olarak harici jwt_tool ile kafa kafaya kıyas yapılır.",
        "en": "Measures TokenGuard's detection on a labeled dataset. It compares two "
              "configurations: **basic** (without weak-key detection) and **all** (with it), "
              "and optionally benchmarks head-to-head against the external jwt_tool."},
    "ev_jwt_tool": {"tr": "jwt_tool.py yolu (opsiyonel, baseline için)",
                    "en": "jwt_tool.py path (optional, for baseline)"},
    "ev_run": {"tr": "Veri kümesini üret & değerlendir", "en": "Generate dataset & evaluate"},
    "ev_dataset": {"tr": "Veri kümesi: {n} token ({pos} güvensiz, {neg} güvenli)",
                   "en": "Dataset: {n} tokens ({pos} insecure, {neg} secure)"},
    "ev_h2h": {"tr": "Ortak kontrollerde kafa kafaya: {labels}",
               "en": "Head-to-head on {labels}"},
    "ev_jwt_notfound": {"tr": "jwt_tool o yolda bulunamadı.",
                        "en": "jwt_tool not found at that path."},
    "ev_jwt_hint": {"tr": "Baseline kıyaslaması için yukarıya bir jwt_tool.py yolu gir.",
                    "en": "Provide a jwt_tool.py path above to add the baseline comparison."},
    "ev_metrics_expander": {"tr": "Metrikler ne anlama gelir?", "en": "What the metrics mean"},
    "ev_metrics_body": {
        "tr": "- **precision (kesinlik)** — İşaretlenenlerin ne kadarı gerçekten doğru. "
              "Düşükse yanlış alarm çoktur.\n"
              "- **recall (duyarlılık)** — Gerçek sorunların ne kadarı yakalandı. Düşükse "
              "kaçırma çoktur.\n"
              "- **F1** — precision ve recall'ın harmonik ortalaması (tek skor).\n"
              "- **FP** — yanlış pozitif (temiz token'da uydurulan bulgu).\n"
              "- **FN** — yanlış negatif (kaçırılan gerçek sorun).\n\n"
              "`basic` zayıf anahtarları kaçırdığı için recall'ı düşüktür; `all` weak_key "
              "ekleyerek tam kapsama ulaşır.",
        "en": "- **precision** — of everything flagged, how much was really correct. Low = "
              "many false alarms.\n"
              "- **recall** — of all real problems, how many were caught. Low = many misses.\n"
              "- **F1** — the harmonic mean of precision and recall (one score).\n"
              "- **FP** — false positives (a finding invented on a clean token).\n"
              "- **FN** — false negatives (a real problem missed).\n\n"
              "`basic` has lower recall because it misses weak keys; `all` adds weak_key for "
              "full coverage."},
    "rb_risk_word": {"tr": "risk", "en": "risk"},
    "rb_findings_word": {"tr": "bulgu", "en": "finding(s)"},
    "rb_noissue": {"tr": "herhangi bir güvenlik sorunu bulunamadı",
                   "en": "no security issues found"},
    "st_timeline": {"tr": "Zaman çizelgesi", "en": "Timeline"},
    "st_remediation": {"tr": "Giderme", "en": "Remediation"},
    "st_download_report": {"tr": "Rapor indir (Markdown)", "en": "Download report (Markdown)"},
    "tl_expired": {"tr": "süresi dolmuş", "en": "expired"},
    "tl_valid": {"tr": "geçerli", "en": "valid"},
    "tl_notyet": {"tr": "henüz geçerli değil", "en": "not yet valid"},
    "tl_active": {"tr": "aktif", "en": "active"},
    "tl_info": {"tr": "bilgi", "en": "info"},
    "lang_label": {"tr": "🌐 Dil / Language", "en": "🌐 Language / Dil"},
}


def t(key: str, **fmt) -> str:
    lang = st.session_state.get("lang", "tr")
    s = STR[key].get(lang, STR[key]["en"])
    return s.format(**fmt) if fmt else s


def server_label(key: str) -> str:
    return t(f"srv_{key}")


# Turkish rendering of engine output (findings / parts / matrix). The engine
# itself stays English (CLI, tests, JSON); only the dashboard localizes for
# display. Keyed by the exact English title, so each finding variant is distinct.
FIND_TR = {
    "Unsigned token (alg=none)": (
        "İmzasız token (alg=none)",
        "Başlık 'none' algoritmasını belirtiyor, yani token imza taşımıyor. Kabul eden "
        "herhangi bir sunucu, saldırganın istediği iddiaları (claim) sahtelemesine izin verir."),
    "Missing 'alg' header": (
        "'alg' başlığı eksik",
        "'alg' değeri olmadan doğrulayıcı bir varsayılana düşebilir ya da doğrulamayı atlayabilir."),
    "Malformed 'alg' header": (
        "Bozuk 'alg' başlığı", "'alg' değeri bir metin (string) değil."),
    "Unknown signing algorithm": (
        "Bilinmeyen imza algoritması",
        "Algoritma standart bir JWS algoritması değil; kütüphaneler bunu öngörülemez "
        "şekilde işleyebilir."),
    "Unexpected signing algorithm": (
        "Beklenmeyen imza algoritması",
        "Algoritma, uygulamanın beklediğinden farklı. Algoritma karışıklığı (ör. RS256 → "
        "HS256) saldırganların açık anahtarla token imzalamasına yol açabilir."),
    "Empty signature": (
        "Boş imza",
        "Başlık bir imza algoritması belirtiyor ama imza bölümü boş; bu, imza kontrolünü "
        "atlayan doğrulayıcıları yoklamanın yaygın bir yoludur."),
    "Embedded public key (jwk)": (
        "Gömülü açık anahtar (jwk)",
        "Token kendi doğrulama anahtarını sağlıyor. Sunucu buna güvenirse, saldırgan kendi "
        "ürettiği anahtarla token imzalayabilir."),
    "Embedded certificate chain (x5c)": (
        "Gömülü sertifika zinciri (x5c)",
        "Token kendi X.509 sertifika zincirini gömüyor. Sunucu güvenilir bir anahtar yerine "
        "gömülü zincirle doğrularsa, saldırgan kendi imzaladığı bir zincir sağlayabilir."),
    "Remote key URL (jku)": (
        "Uzak anahtar URL'si (jku)",
        "'jku' başlığı doğrulayıcıyı anahtarı için bir URL'ye yönlendirir. Katı bir izin "
        "listesi olmadan saldırganlar kendi anahtarlarını barındırabilir."),
    "Remote key URL (x5u)": (
        "Uzak anahtar URL'si (x5u)",
        "'x5u' başlığı doğrulayıcıyı anahtarı için bir URL'ye yönlendirir. Katı bir izin "
        "listesi olmadan saldırganlar kendi anahtarlarını barındırabilir."),
    "Suspicious 'kid' value": (
        "Şüpheli 'kid' değeri",
        "Anahtar kimliği (kid) dizin aşımı (path traversal) veya enjeksiyon karakterleri "
        "içeriyor; bu, 'kid'i dosya yollarında veya veritabanı sorgularında kullanan "
        "sunucuları kötüye kullanabilir."),
    "No expiration time (exp)": (
        "Son kullanma yok (exp)",
        "Token hiç sona ermiyor. Çalınırsa süresiz olarak tekrar kullanılabilir."),
    "Malformed 'exp' claim": (
        "Bozuk 'exp' iddiası", "'exp' bir NumericDate (epoch'tan beri saniye) olmalı."),
    "Token has expired": (
        "Token süresi dolmuş",
        "Token son kullanma zamanını geçmiş. Reddedilmeli; bir sunucu hâlâ kabul ediyorsa "
        "son kullanma uygulanmıyor demektir."),
    "Excessively long token lifetime": (
        "Aşırı uzun token ömrü",
        "Token, yapılandırılmış maksimumdan daha uzun süre geçerli. Uzun ömürlü token'lar "
        "tekrar saldırısı (replay) penceresini genişletir."),
    "No audience (aud)": (
        "Hedef kitle yok (aud)",
        "Hedef kitle olmadan token belirli bir servise bağlı değildir ve aynı vericiye "
        "güvenen başka servislerce kabul edilebilir (token yeniden kullanımı)."),
    "No issuer (iss)": (
        "Verici yok (iss)",
        "Verici olmadan doğrulayıcı token'ı kimin oluşturduğunu doğrulayamaz."),
    "Token not yet valid (nbf)": (
        "Token henüz geçerli değil (nbf)", "'nbf' zamanı gelecekte."),
    "Sensitive data in payload": (
        "Yükte hassas veri",
        "JWT yükleri yalnızca Base64URL ile kodlanır, şifrelenmez. Token'ı elinde tutan "
        "herkes bu değerleri okuyabilir."),
    "Weak HMAC signing key recovered": (
        "Zayıf HMAC imza anahtarı kurtarıldı",
        "İmza sırrı, yaygın sırlardan oluşan bir wordlist'te bulundu. Sırrı ele geçiren "
        "saldırgan istediği iddialarla geçerli token üretebilir."),
    "Abused 'crit' header": (
        "İstismar edilmiş 'crit' başlığı",
        "'crit' başlığı, doğrulayıcının anlaması gereken uzantıları listeler ama burada "
        "kötüye kullanılmış. 'crit'i yok sayan veya yanlış işleyen doğrulayıcılar, tam "
        "işlemedikleri bir token'ı kabul etmeye kandırılabilir."),
    "Duplicate JSON keys": (
        "Yinelenen JSON anahtarları",
        "JSON yinelenen anahtarlar içeriyor. JWT kütüphaneleri yinelenenleri farklı çözer "
        "(ilk vs son kazanır); saldırgan, bir bileşenin doğruladığı ama başka bir bileşenin "
        "farklı değerlere güvendiği tek bir token üretebilir (parser differential / iddia "
        "kaçakçılığı)."),
}

PART_TR = {"header": "başlık", "payload": "yük", "signature": "imza"}

# Active-matrix cell labels and common hover notes.
MATRIX_TR = {"accept": "kabul", "reject?": "ret?", "VULN": "AÇIK",
             "rejected": "reddedildi", "skip": "atla"}
NOTE_TR = {
    "skipped: secret not in wordlist": "atlandı: sır wordlist'te yok",
    "secret recovered from wordlist": "sır wordlist'ten kurtarıldı",
    "could not obtain a baseline token from the server; attacks skipped":
        "sunucudan temel (baseline) token alınamadı; saldırılar atlandı",
}


def is_tr() -> bool:
    return st.session_state.get("lang", "tr") == "tr"


def loc_finding(f):
    """Return (title, explanation, part) localized for the current language."""
    if not is_tr():
        return f.title, f.explanation, f.part
    ttl, expl = FIND_TR.get(f.title, (f.title, f.explanation))
    return ttl, expl, PART_TR.get(f.part, f.part)


def mlabel(txt: str) -> str:
    return MATRIX_TR.get(txt, txt) if is_tr() else txt


def mnote(note: str) -> str:
    return NOTE_TR.get(note, note) if is_tr() else note


# Turkish remediation advice (engine REMEDIATION stays English/canonical).
REMED_TR = {
    "ALG_NONE": "alg=none'u reddet; kütüphaneyi imza algoritmaları için açık bir izin "
                "listesiyle yapılandır.",
    "ALG_MISSING": "Açık bir 'alg' iste ve onu bir izin listesine göre doğrula.",
    "ALG_UNKNOWN": "Yalnızca sabit bir izin listesindeki bilinen algoritmaları kabul et.",
    "ALG_UNEXPECTED": "Uygulamanın kullandığı tam algoritma(ları) sabitle ve başkasını "
                      "reddet (RS256→HS256 karışıklığını önler).",
    "SIGNATURE_EMPTY": "Boş olmayan bir imza iste ve doğrula; imzasız token kabul etme.",
    "HEADER_JWK": "Token'a gömülü anahtara ('jwk') asla güvenme; yalnızca güvenilir "
                  "sunucu-taraflı kaynaktan anahtar kullan.",
    "HEADER_X5C": "Token'a gömülü sertifika zinciriyle ('x5c') doğrulama yapma; güvenilir "
                  "sertifikaları sunucu tarafında sabitle.",
    "HEADER_KEY_URL": "Token'ın verdiği URL'lerden ('jku'/'x5u') anahtar çekme; katı bir "
                      "anahtar kaynağı izin listesi kullan.",
    "HEADER_KID_INJECTION": "'kid'i opak bir kimlik olarak ele al; sabit bir eşlemede ara, "
                            "asla dosya yolu veya SQL sorgusunda kullanma.",
    "CRIT_HEADER": "'crit' kötü biçimliyse, standart bir başlığa veya desteklemediğin bir "
                   "başlığa atıf yapıyorsa token'ı reddet.",
    "DUPLICATE_KEYS": "Header veya payload JSON'u yinelenen anahtar içeren token'ları "
                      "reddet; katı bir parser kullan.",
    "MISSING_EXP": "Bir 'exp' iddiası iste ve her istekte uygula.",
    "INVALID_EXP": "'exp'in sayısal tarih (epoch'tan beri saniye) olmasını iste ve kötü "
                   "biçimli değerleri reddet.",
    "EXPIRED": "Süresi dolmuş token'ları reddet; 'exp'i minimum saat kayması ile şu anki "
               "zamana göre doğrula.",
    "LONG_LIFETIME": "Kısa ömürlü erişim token'ları (dakikalar) ver ve uzun oturumlar için "
                     "yenileme (refresh) token'ı kullan.",
    "MISSING_AUD": "Bir 'aud' iddiası ayarla ve doğrula; böylece token yalnızca hedef "
                   "servisçe kabul edilir.",
    "MISSING_ISS": "Bir 'iss' iddiası ayarla ve beklenen vericiye göre doğrula.",
    "NOT_YET_VALID": "'nbf'i doğrula ve henüz geçerli olmayan token'ları reddet (saat "
                     "senkronizasyonunu kontrol et).",
    "SENSITIVE_DATA": "JWT yüküne asla sır veya kişisel veri koyma; yalnızca Base64 ile "
                      "kodlanır, şifrelenmez.",
    "WEAK_KEY": "Uzun, rastgele bir HMAC sırrı (≥32 bayt) kullan veya asimetrik anahtarlara "
                "geç; sızan sırrı değiştir.",
}

REPORT_LABELS_TR = {
    "report_title": "TokenGuard Analiz Raporu", "generated": "Oluşturulma",
    "overall_risk": "Genel risk", "findings": "Bulgular", "token": "Token",
    "algorithm": "Algoritma", "type": "Tür",
    "iat": "Verilme (iat)", "nbf": "Geçerlilik başlangıcı (nbf)", "exp": "Son kullanma (exp)",
    "header": "Başlık", "payload": "Yük", "evidence": "Kanıt", "remediation": "Giderme",
    "no_issues": "Sorun bulunamadı.",
    "risk_ok": "GÜVENLİ", "risk_critical": "KRİTİK", "risk_high": "YÜKSEK",
    "risk_medium": "ORTA", "risk_low": "DÜŞÜK", "risk_info": "BİLGİ",
}

RISK_WORD = {
    "tr": {"OK": "GÜVENLİ", "CRITICAL": "KRİTİK", "HIGH": "YÜKSEK", "MEDIUM": "ORTA",
           "LOW": "DÜŞÜK", "INFO": "BİLGİ"},
    "en": {"OK": "SECURE", "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
           "LOW": "LOW", "INFO": "INFO"},
}
RISK_BANNER_COLOR = {"OK": GREEN, "CRITICAL": RED, "HIGH": RED, "MEDIUM": AMBER,
                     "LOW": AMBER, "INFO": GREY}
TL_STATE_KEY = {"expired": "tl_expired", "valid": "tl_valid", "not-yet-valid": "tl_notyet",
                "active": "tl_active", "info": "tl_info"}
TL_COLOR = {"expired": RED, "valid": GREEN, "not-yet-valid": AMBER, "active": GREEN,
            "info": GREY}


def report_localize(f):
    ttl, expl, part = loc_finding(f)
    remed = (REMED_TR.get(f.rule_id) if is_tr() else None) or REMEDIATION.get(f.rule_id, "")
    return ttl, expl, part, remed


def build_report(parsed, findings, now) -> str:
    return to_markdown(parsed, findings, now,
                       labels=REPORT_LABELS_TR if is_tr() else None,
                       localize=report_localize, lang="tr" if is_tr() else "en")


def render_risk_banner(findings):
    lvl = risk_level(findings)
    word = RISK_WORD["tr" if is_tr() else "en"][lvl]
    if lvl == "OK":
        st.success(f"✅ {word} — {t('rb_noissue')}")
        return
    msg = f"{word} {t('rb_risk_word')} — {len(findings)} {t('rb_findings_word')}"
    fn = st.error if lvl in ("CRITICAL", "HIGH") else (
        st.warning if lvl in ("MEDIUM", "LOW") else st.info)
    fn(f"⚠️ {msg}")


def render_timeline(payload, now):
    rows = claim_timeline(payload, now)
    if not rows:
        return
    st.markdown(f"**{t('st_timeline')}**")
    lang = "tr" if is_tr() else "en"
    for r in rows:
        color = TL_COLOR.get(r["state"], GREY)
        state_txt = t(TL_STATE_KEY.get(r["state"], "tl_info"))
        label = REPORT_LABELS_TR.get(r["claim"], r["label"]) if is_tr() else r["label"]
        rel = relative_phrase(r["claim"], r["delta"], lang)
        st.markdown(
            f"<span class='tg-dot' style='background:{color}'></span>"
            f"<b>{html.escape(label)}</b> &nbsp;{r['when']} &nbsp;"
            f"<span style='color:#8e99ab'>({html.escape(rel)})</span> &nbsp;"
            f"<span class='tg-badge' style='background:{color}'>{state_txt}</span>",
            unsafe_allow_html=True)


def _active_label(r):
    if r.status is None:
        return "skipped"
    if r.expected_accept:
        return "accept" if r.accepted else "reject?"
    return "VULN" if r.vulnerable else "rejected"


def build_active_report(results) -> str:
    from tokenguard.active.runner import summarize
    tr = is_tr()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    vuln = sum(1 for r in results if r.vulnerable)
    out = ["# " + ("TokenGuard — Aktif Test Raporu" if tr else "TokenGuard — Active Testing Report"), ""]
    out.append(("**Oluşturulma:** " if tr else "**Generated:** ") + now)
    out.append(("**Zafiyetli yanıt:** " if tr else "**Vulnerable responses:** ") + str(vuln))
    out.append("")
    out.append("## " + ("Ham sonuçlar" if tr else "Raw results"))
    out.append("| endpoint | attack | status | result | note |")
    out.append("|---|---|---|---|---|")
    for r in results:
        out.append(f"| {r.endpoint} | {r.attack} | {r.status if r.status is not None else '-'} "
                   f"| {_active_label(r)} | {r.note or ''} |")
    out.append("")
    out.append("## " + ("Endpoint başına açıklar" if tr else "Flaws per endpoint"))
    for ep, flaws in summarize(results).items():
        out.append(f"- **{ep}** → " + (", ".join(flaws) if flaws
                   else ("açık yok" if tr else "no flaws")))
    return "\n".join(out) + "\n"


def build_eval_report(n, pos, table, pc) -> str:
    tr = is_tr()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    out = ["# " + ("TokenGuard — Değerlendirme Raporu" if tr else "TokenGuard — Evaluation Report"), ""]
    out.append(("**Oluşturulma:** " if tr else "**Generated:** ") + now)
    out.append(("**Veri kümesi:** " if tr else "**Dataset:** ")
               + f"{n} ({pos} " + ("güvensiz, " if tr else "insecure, ")
               + f"{n - pos} " + ("güvenli)" if tr else "secure)"))
    out.append("")
    out.append("## " + ("Konfigürasyonlar" if tr else "Configurations"))
    out.append("| config | precision | recall | F1 | FP | FN |")
    out.append("|---|---|---|---|---|---|")
    for name, s in table.items():
        out.append(f"| {name} | {s['precision']:.3f} | {s['recall']:.3f} | {s['F1']:.3f} "
                   f"| {s['FP']} | {s['FN']} |")
    out.append("")
    out.append("## " + ("Sınıf başına (all)" if tr else "Per-class (all)"))
    out.append("| rule_id | support | precision | recall |")
    out.append("|---|---|---|---|")
    for rid, s in pc.items():
        out.append(f"| {rid} | {s['support']} | {s['precision']:.2f} | {s['recall']:.2f} |")
    return "\n".join(out) + "\n"


CSS = """
<style>
.tg-header{background:linear-gradient(100deg,#15233f 0%,#0e1117 70%);
  padding:20px 24px;border-radius:14px;border:1px solid #243049;margin-bottom:14px}
.tg-header h1{margin:0;font-size:1.7rem;letter-spacing:-0.5px}
.tg-header p{margin:4px 0 0;color:#8e99ab;font-size:0.95rem}
.tg-card{background:#141a24;border:1px solid #222c3c;border-radius:12px;padding:16px 18px}
.tg-metric{background:#141a24;border:1px solid #222c3c;border-radius:12px;padding:14px 16px;text-align:center}
.tg-metric .v{font-size:1.9rem;font-weight:700;line-height:1.1}
.tg-metric .l{color:#8e99ab;font-size:0.8rem;margin-top:2px}
.tg-badge{color:#fff;padding:2px 9px;border-radius:5px;font-size:0.76em;font-weight:700;letter-spacing:0.3px}
.tg-finding{background:#141a24;border:1px solid #222c3c;border-radius:11px;
  padding:12px 15px;margin-bottom:10px}
.tg-finding b{font-size:1.02em}
.tg-rule{font-family:ui-monospace,Menlo,monospace;background:#1f2838;padding:1px 7px;
  border-radius:5px;font-size:0.78em;color:#aeb8c8}
.tg-part{color:#7f8a9c;font-style:italic;font-size:0.84em}
.tg-body{color:#c3ccda;margin-top:7px;font-size:0.92em;line-height:1.45}
.tg-ev{font-family:ui-monospace,Menlo,monospace;background:#0b0f16;border:1px solid #222c3c;
  border-radius:7px;padding:7px 10px;margin-top:8px;color:#8fd6a6;font-size:0.82em;display:block;
  overflow-x:auto}
.tg-fix{margin-top:8px;padding:7px 10px;background:#0f1a14;border:1px solid #1f3a2a;
  border-radius:7px;color:#bfe6cc;font-size:0.86em;line-height:1.4}
.tg-matrix{width:100%;border-collapse:separate;border-spacing:4px;margin-top:6px}
.tg-matrix th{font-size:0.7rem;color:#8e99ab;font-weight:600;padding:3px 2px;text-align:center}
.tg-matrix td{text-align:center;border-radius:7px;font-size:0.76rem;padding:7px 5px;color:#fff;
  font-weight:600;line-height:1.25}
.tg-matrix td .s{display:block;font-weight:400;font-size:0.82em;opacity:0.85}
.tg-epname{text-align:left!important;color:#e2e7f0!important;background:#1b2230;font-weight:600}
.tg-dot{height:9px;width:9px;border-radius:50%;display:inline-block;margin-right:7px}
</style>
"""


# ----------------------------------------------------------------- server control

def _ping(base: str, path: str) -> bool:
    import requests
    try:
        requests.get(base + path, timeout=1.0)
        return True
    except requests.RequestException:
        return False


def is_up(key: str) -> bool:
    _, base, path = SERVERS[key]
    return _ping(base, path)


def start_server(key: str):
    if is_up(key):
        return
    cmd, _, _ = SERVERS[key]
    proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    st.session_state.setdefault("procs", {})[key] = proc
    for _ in range(20):
        time.sleep(0.25)
        if is_up(key):
            break


def stop_server(key: str):
    proc = st.session_state.get("procs", {}).get(key)
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
    st.session_state.get("procs", {}).pop(key, None)


def server_controls():
    st.sidebar.header(t("sidebar_servers"))
    for key in SERVERS:
        up = is_up(key)
        color = GREEN if up else "#555c68"
        st.sidebar.markdown(
            f"<span class='tg-dot' style='background:{color}'></span><b>{server_label(key)}</b>  "
            f"<span style='color:#8e99ab;font-size:0.8em'>"
            f"{t('running') if up else t('stopped')}</span>",
            unsafe_allow_html=True)
        c1, c2 = st.sidebar.columns(2)
        c1.button(t("start"), key=f"start_{key}", disabled=up,
                  on_click=start_server, args=(key,), use_container_width=True)
        c2.button(t("stop"), key=f"stop_{key}", disabled=not up,
                  on_click=stop_server, args=(key,), use_container_width=True)
    st.sidebar.caption(t("servers_caption"))


# ----------------------------------------------------------------- widgets

def badge(sev: str) -> str:
    return (f"<span class='tg-badge' style='background:{SEV_COLOR.get(sev, GREY)}'>"
            f"{sev}</span>")


def metric_card(value, label, color="#e6e9ef") -> str:
    return (f"<div class='tg-metric'><div class='v' style='color:{color}'>{value}</div>"
            f"<div class='l'>{label}</div></div>")


def severity_chart(counts):
    data = pd.DataFrame({"severity": SEV_ORDER, "count": [counts[s] for s in SEV_ORDER]})
    chart = (alt.Chart(data).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
             .encode(
                 x=alt.X("severity:N", sort=SEV_ORDER, title=None,
                         axis=alt.Axis(labelAngle=0)),
                 y=alt.Y("count:Q", title="findings", axis=alt.Axis(tickMinStep=1)),
                 color=alt.Color("severity:N",
                                 scale=alt.Scale(domain=SEV_ORDER,
                                                 range=[SEV_COLOR[s] for s in SEV_ORDER]),
                                 legend=None),
                 tooltip=["severity", "count"])
             .properties(height=230))
    st.altair_chart(chart, use_container_width=True)


def render_findings(findings):
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        counts[str(f.severity)] += 1
    cols = st.columns(len(SEV_ORDER))
    for col, sev in zip(cols, SEV_ORDER):
        col.markdown(metric_card(counts[sev], sev, SEV_COLOR[sev]), unsafe_allow_html=True)
    st.write("")
    severity_chart(counts)
    st.write("")
    for f in findings:
        ttl, expl, part, remed = report_localize(f)
        ev = (f"<span class='tg-ev'>{html.escape(f.evidence)}</span>") if f.evidence else ""
        remed_html = (f"<div class='tg-fix'>🛠 <b>{t('st_remediation')}:</b> "
                      f"{html.escape(remed)}</div>") if remed else ""
        st.markdown(
            f"<div class='tg-finding' style='border-left:4px solid {SEV_COLOR.get(str(f.severity), GREY)}'>"
            f"<div>{badge(str(f.severity))} &nbsp;<b>{html.escape(ttl)}</b> &nbsp;"
            f"<span class='tg-rule'>{f.rule_id}</span> &nbsp;<span class='tg-part'>{html.escape(part)}</span></div>"
            f"<div class='tg-body'>{html.escape(expl)}</div>{ev}{remed_html}</div>",
            unsafe_allow_html=True)


# ----------------------------------------------------------------- page

st.set_page_config(page_title="TokenGuard", page_icon="🛡️", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)

# Language switch (must run before any t() below)
_lang_choice = st.sidebar.radio(STR["lang_label"]["tr"], ["Türkçe", "English"],
                                key="lang_choice", horizontal=True)
st.session_state["lang"] = "tr" if _lang_choice == "Türkçe" else "en"
st.sidebar.divider()

st.markdown(
    f"<div class='tg-header'><h1>🛡️ TokenGuard</h1>"
    f"<p>{t('subtitle')}</p></div>", unsafe_allow_html=True)
server_controls()

tab_dash, tab_static, tab_active, tab_mcp, tab_eval = st.tabs(
    [t("tab_overview"), t("tab_static"), t("tab_active"), t("tab_mcp"), t("tab_eval")])


# ================================================================= Overview
def run_all():
    out = {}
    if is_up("vuln"):
        from tokenguard.active.runner import HttpClient, run_active_tests, summarize
        try:
            res = run_active_tests(client=HttpClient("http://127.0.0.1:5000"))
            flaws = sum(len(v) for v in summarize(res).values())
            out["active"] = {"flaws": flaws, "endpoints": len(summarize(res))}
        except Exception as exc:  # noqa: BLE001
            out["active_error"] = str(exc)
    from tokenguard.mcp_probe import run_mcp_probe, vulnerabilities
    for key, port in (("mcp_secure", 7000), ("mcp_insecure", 7001)):
        if is_up(key):
            try:
                res = run_mcp_probe(f"http://127.0.0.1:{port}")
                out[key] = {"vulns": len(vulnerabilities(res))}
            except Exception as exc:  # noqa: BLE001
                out[f"{key}_error"] = str(exc)
    try:
        import dataset.generate as gen
        from evaluation.evaluate import CONFIGS, LABELED, load, score, tokenguard_ids
        gen.main([])
        records = load()
        s = score(records, lambda rec: tokenguard_ids(rec, CONFIGS["all"]), LABELED)
        out["eval"] = {"recall": s["recall"], "precision": s["precision"],
                       "f1": s["f1"], "fp": s["fp"]}
    except Exception as exc:  # noqa: BLE001
        out["eval_error"] = str(exc)
    out["_ts"] = time.strftime("%H:%M:%S")
    return out


with tab_dash:
    st.info(t("ov_intro"))
    st.subheader(t("ov_server_status"))
    cols = st.columns(len(SERVERS))
    for col, key in zip(cols, SERVERS):
        up = is_up(key)
        col.markdown(metric_card(t("running") if up else t("stopped"), server_label(key),
                                 GREEN if up else "#868e96"), unsafe_allow_html=True)

    st.write("")
    st.subheader(t("ov_summary"))
    st.caption(t("ov_summary_caption"))
    if st.button(t("ov_run_all"), type="primary"):
        with st.spinner(t("ov_spinner")):
            st.session_state["runall"] = run_all()

    summary = st.session_state.get("runall")
    if summary:
        st.caption(t("ov_last_run", ts=summary["_ts"]))
        c = st.columns(4)
        active = summary.get("active")
        c[0].markdown(metric_card(
            active["flaws"] if active else "—", t("m_active_flaws"),
            RED if active and active["flaws"] else GREEN), unsafe_allow_html=True)
        ms = summary.get("mcp_secure")
        c[1].markdown(metric_card(
            ms["vulns"] if ms else "—", t("m_mcp_secure"),
            RED if ms and ms["vulns"] else GREEN), unsafe_allow_html=True)
        mi = summary.get("mcp_insecure")
        c[2].markdown(metric_card(
            mi["vulns"] if mi else "—", t("m_mcp_misconfig"),
            RED if mi and mi["vulns"] else "#868e96"), unsafe_allow_html=True)
        ev = summary.get("eval")
        c[3].markdown(metric_card(
            f"{ev['recall']:.2f}" if ev else "—", t("m_recall"),
            "#4dabf7"), unsafe_allow_html=True)
        downs = [k for k in ("vuln", "mcp_secure", "mcp_insecure") if not is_up(k)]
        if downs:
            st.info(t("ov_skipped", names=", ".join(server_label(k) for k in downs)))

    st.write("")
    with st.expander(t("ov_tabs_expander")):
        st.markdown(t("ov_tabs_body"))


# ================================================================= Static
with tab_static:
    st.subheader(t("st_title"))
    st.info(t("st_intro"))
    groups = st.multiselect(t("st_groups"), list(ALL_GROUPS), default=list(ALL_GROUPS),
                            help=t("st_groups_help"))
    cc1, cc2 = st.columns(2)
    max_life_h = cc1.number_input(t("st_maxlife"), 1, 8760, 24, help=t("st_maxlife_help"))
    expected = cc2.text_input(t("st_expected"), "", help=t("st_expected_help"))

    token = st.text_area(t("st_token"), height=120, placeholder="eyJ...", key="tok")
    st.button(t("st_load_sample"),
              on_click=lambda: st.session_state.update(tok=SAMPLE_NONE))

    with st.expander(t("sev_expander")):
        st.markdown(t("sev_body"))

    if token.strip():
        try:
            parsed = parse_token(token)
        except TokenParseError as exc:
            st.error(t("st_parse_err", err=exc))
        else:
            cfg = AnalysisConfig(
                max_lifetime_seconds=int(max_life_h) * 3600,
                expected_algs=[a.strip() for a in expected.split(",") if a.strip()] or None)
            findings = analyze(parsed, groups=groups or list(ALL_GROUPS), config=cfg)
            now = cfg.current_time()
            render_risk_banner(findings)
            left, right = st.columns(2)
            left.caption(t("st_header")); left.json(parsed.header)
            right.caption(t("st_payload")); right.json(parsed.payload)
            render_timeline(parsed.payload, now)
            st.write("")
            st.subheader(t("st_findings", n=len(findings)))
            if not findings:
                st.success(t("st_no_issues"))
            else:
                render_findings(findings)
            dl1, dl2 = st.columns(2)
            dl1.download_button(t("st_download_report"),
                                build_report(parsed, findings, now),
                                file_name="tokenguard_report.md", use_container_width=True)
            if findings:
                dl2.download_button(t("st_download_findings"),
                                    json.dumps([f.to_dict() for f in findings], indent=2),
                                    file_name="tokenguard_findings.json",
                                    use_container_width=True)


# ================================================================= Active
def active_matrix(results):
    attacks = ["NO_TOKEN", "BASELINE_VALID", "ALG_NONE", "TAMPERED_SIGNATURE",
               "EXPIRED_TOKEN", "WRONG_AUDIENCE", "WEAK_KEY_FORGERY"]
    endpoints = sorted({r.endpoint for r in results})
    cell = {(r.endpoint, r.attack): r for r in results}

    def td(r):
        if r is None or r.status is None:
            note = f" title='{html.escape(mnote(r.note))}'" if r is not None and r.note else ""
            return (f"<td style='background:#343a46;color:#9aa4b2'{note}>–"
                    f"<span class='s'>{mlabel('skip')}</span></td>")
        note = html.escape(mnote(r.note)) if r.note else ""
        if r.expected_accept:
            bg, txt = (GREEN, "accept") if r.accepted else (AMBER, "reject?")
        elif r.vulnerable:
            bg, txt = RED, "VULN"
        else:
            bg, txt = GREEN, "rejected"
        return (f"<td style='background:{bg}' title='{note}'>{mlabel(txt)}"
                f"<span class='s'>{r.status}</span></td>")

    head = "".join(f"<th>{a.replace('_', ' ')}</th>" for a in attacks)
    rows = ""
    for ep in endpoints:
        cells = "".join(td(cell.get((ep, a))) for a in attacks)
        rows += f"<tr><td class='tg-epname'>{ep}</td>{cells}</tr>"
    st.markdown(f"<table class='tg-matrix'><tr><th></th>{head}</tr>{rows}</table>",
                unsafe_allow_html=True)


with tab_active:
    st.subheader(t("act_title"))
    st.info(t("act_intro"))
    up = is_up("vuln")
    dot = GREEN if up else "#555c68"
    st.markdown(f"<span class='tg-dot' style='background:{dot}'></span>"
                + (t("act_server_running") if up else t("act_server_stopped")),
                unsafe_allow_html=True)
    target = st.text_input(t("act_target"), "http://127.0.0.1:5000")
    secret = st.text_input(t("act_secret"), "", help=t("act_secret_help"))
    with st.expander(t("act_attacks_expander")):
        st.markdown(t("act_attacks_body"))
    if st.button(t("act_run"), disabled=not up, type="primary"):
        from tokenguard.active.runner import HttpClient, run_active_tests
        try:
            st.session_state["active_res"] = run_active_tests(
                client=HttpClient(target), secret=secret or None)
        except Exception as exc:  # noqa: BLE001
            st.error(f"{type(exc).__name__}: {exc}")
            st.session_state.pop("active_res", None)

    results = st.session_state.get("active_res")
    if results:
        from tokenguard.active.runner import summarize
        active_matrix(results)
        st.caption(t("act_matrix_legend"))
        st.subheader(t("act_flaws_title"))
        for ep, flaws in summarize(results).items():
            icon = "🔴" if flaws else "🟢"
            st.write(f"{icon} **{ep}** → {', '.join(flaws) if flaws else t('act_no_flaws')}")
        d1, d2 = st.columns(2)
        d1.download_button(t("st_download_report"), build_active_report(results),
                           file_name="tokenguard_active_report.md", use_container_width=True)
        d2.download_button(t("act_download"),
                           json.dumps([r.to_dict() for r in results], indent=2),
                           file_name="tokenguard_active_results.json", use_container_width=True)


# ================================================================= MCP
with tab_mcp:
    st.subheader(t("mcp_title"))
    st.info(t("mcp_intro"))
    c1, c2 = st.columns(2)
    for col, key in ((c1, "mcp_secure"), (c2, "mcp_insecure")):
        up = is_up(key)
        col.markdown(f"<span class='tg-dot' style='background:{GREEN if up else '#555c68'}'>"
                     f"</span>{server_label(key)} — {t('running') if up else t('stopped')}",
                     unsafe_allow_html=True)
    mcp_target = st.text_input(t("mcp_target"), "http://127.0.0.1:7000")
    with st.expander(t("mcp_checks_expander")):
        st.markdown(t("mcp_checks_body"))
    if st.button(t("mcp_run"), type="primary"):
        from tokenguard.mcp_probe import run_mcp_probe
        try:
            st.session_state["mcp_res"] = run_mcp_probe(mcp_target)
        except Exception as exc:  # noqa: BLE001
            st.error(f"{type(exc).__name__}: {exc}")
            st.session_state.pop("mcp_res", None)

    results = st.session_state.get("mcp_res")
    if results:
        from tokenguard.mcp_probe import vulnerabilities
        for r in results:
            if r.passed:
                dot, tag = GREEN, "PASS"
            elif r.vulnerability:
                dot, tag = RED, r.vulnerability
            else:
                dot, tag = AMBER, "FAIL"
            st.markdown(
                f"<div class='tg-finding' style='border-left:4px solid {dot}'>"
                f"<b>{r.check}</b> &nbsp;<span class='tg-badge' style='background:{dot}'>{tag}"
                f"</span><div class='tg-body'>{html.escape(r.detail)}</div></div>",
                unsafe_allow_html=True)
        vulns = vulnerabilities(results)
        if vulns:
            st.error(t("mcp_vulns", v=", ".join(vulns)))
        else:
            st.success(t("mcp_no_vulns"))


# ================================================================= Evaluation
with tab_eval:
    st.subheader(t("ev_title"))
    st.info(t("ev_intro"))
    with st.expander(t("ev_metrics_expander")):
        st.markdown(t("ev_metrics_body"))
    jwt_tool_path = st.text_input(t("ev_jwt_tool"), "")
    if st.button(t("ev_run"), type="primary"):
        import dataset.generate as gen
        from evaluation.evaluate import (ALL_GROUPS as EVAL_ALL, CONFIGS, LABELED, load,
                                         per_class, score, tokenguard_ids)
        from evaluation.baselines import OVERLAP_LABELS, JwtTool

        gen.main([])
        records = load()
        pos = sum(1 for r in records if r["labels"])
        st.caption(t("ev_dataset", n=len(records), pos=pos, neg=len(records) - pos))

        table = {}
        for name, grp in CONFIGS.items():
            s = score(records, lambda rec, g=grp: tokenguard_ids(rec, g), LABELED)
            table[name] = {"precision": s["precision"], "recall": s["recall"],
                           "F1": s["f1"], "FP": s["fp"], "FN": s["fn"]}
        df = pd.DataFrame(table).T
        st.dataframe(df.style.format({"precision": "{:.3f}", "recall": "{:.3f}",
                                      "F1": "{:.3f}"}), use_container_width=True)
        melted = df[["precision", "recall", "F1"]].reset_index().melt(
            "index", var_name="metric", value_name="score")
        chart = (alt.Chart(melted).mark_bar()
                 .encode(x=alt.X("metric:N", title=None, axis=alt.Axis(labelAngle=0)),
                         y=alt.Y("score:Q", scale=alt.Scale(domain=[0, 1])),
                         color=alt.Color("index:N", title="config"),
                         xOffset="index:N", tooltip=["index", "metric", "score"])
                 .properties(height=260))
        st.altair_chart(chart, use_container_width=True)

        pc = per_class(records, lambda rec: tokenguard_ids(rec, EVAL_ALL), LABELED)
        st.download_button(t("st_download_report"),
                           build_eval_report(len(records), pos, table, pc),
                           file_name="tokenguard_eval_report.md")

        jt = JwtTool.locate(jwt_tool_path or None)
        if jt.available:
            st.subheader(t("ev_h2h", labels=sorted(OVERLAP_LABELS)))
            tg = score(records, lambda rec: tokenguard_ids(rec, EVAL_ALL), OVERLAP_LABELS)
            bl = score(records, lambda rec: jt.labels(rec["token"]), OVERLAP_LABELS)
            h2h = pd.DataFrame({
                "TokenGuard": {"precision": tg["precision"], "recall": tg["recall"], "F1": tg["f1"]},
                "jwt_tool": {"precision": bl["precision"], "recall": bl["recall"], "F1": bl["f1"]},
            }).T
            st.dataframe(h2h.style.format("{:.3f}"), use_container_width=True)
        elif jwt_tool_path:
            st.warning(t("ev_jwt_notfound"))
        else:
            st.caption(t("ev_jwt_hint"))
