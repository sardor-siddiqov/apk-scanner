import hashlib
import os
import re
from typing import Any, Dict, List
import logging

logging.getLogger("androguard").setLevel(logging.ERROR)

from androguard.misc import AnalyzeAPK

from .constants import DANGEROUS_PERMISSIONS, HIGH_RISK_KEYWORDS


URL_REGEX = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def safe_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def get_file_extension(file_path: str) -> str:
    return os.path.splitext(file_path)[1].lower()


def get_file_size(file_path: str) -> int:
    return os.path.getsize(file_path)


def calculate_file_hashes(file_path: str) -> Dict[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
            md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "md5": md5.hexdigest(),
    }


def extract_strings(dx) -> List[str]:
    strings = []
    try:
        for s in dx.strings:
            value = getattr(s, "value", None)
            if value and isinstance(value, str):
                strings.append(value)
    except Exception:
        pass
    return strings


def detect_urls(strings: List[str]) -> List[str]:
    found = set()
    for text in strings:
        for match in URL_REGEX.findall(text):
            found.add(match)
    return sorted(found)


def detect_ips(strings: List[str]) -> List[str]:
    found = set()
    for text in strings:
        for match in IP_REGEX.findall(text):
            found.add(match)
    return sorted(found)


def detect_obfuscation(class_names: List[str]) -> int:
    if not class_names:
        return 0

    suspicious = 0
    for name in class_names:
        parts = name.strip("L;").split("/")
        last = parts[-1] if parts else name

        if len(last) <= 2:
            suspicious += 1

        short_parts = sum(1 for p in parts if len(p) <= 2)
        if short_parts >= 3:
            suspicious += 1

    score = int((suspicious / max(len(class_names), 1)) * 100)
    return min(score, 100)


def count_exported_components(apk) -> Dict[str, int]:
    exported_activities = 0
    exported_services = 0
    exported_receivers = 0
    exported_providers = 0

    try:
        activities = apk.get_activities() or []
        exported_activities = len(activities)
    except Exception:
        pass

    try:
        services = apk.get_services() or []
        exported_services = len(services)
    except Exception:
        pass

    try:
        receivers = apk.get_receivers() or []
        exported_receivers = len(receivers)
    except Exception:
        pass

    try:
        providers = apk.get_providers() or []
        exported_providers = len(providers)
    except Exception:
        pass

    return {
        "activities": exported_activities,
        "services": exported_services,
        "receivers": exported_receivers,
        "providers": exported_providers,
        "total": exported_activities + exported_services + exported_receivers + exported_providers,
    }


def calculate_risk(
    permissions: List[str],
    urls: List[str],
    ips: List[str],
    strings: List[str],
    obfuscation_score: int,
    exported_components_total: int,
) -> Dict[str, Any]:
    score = 0
    notes = []

    dangerous_permissions = []
    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS:
            dangerous_permissions.append(perm)
            score += DANGEROUS_PERMISSIONS[perm]

    joined_lower = " ".join(strings).lower()

    uses_accessibility = "accessibility" in joined_lower or any(
        "BIND_ACCESSIBILITY_SERVICE" in p for p in permissions
    )
    uses_sms = any("SMS" in p for p in permissions)
    uses_overlay = any("SYSTEM_ALERT_WINDOW" in p for p in permissions)

    if uses_accessibility:
        score += 20
        notes.append("Accessibility bilan bog‘liq izlar topildi.")

    if uses_sms:
        score += 15
        notes.append("SMS bilan bog‘liq permissionlar topildi.")

    if uses_overlay:
        score += 12
        notes.append("Overlay permission topildi.")

    if uses_accessibility and uses_overlay:
        score += 15
        notes.append("Accessibility va overlay birga ishlatilmoqda.")

    if urls:
        score += min(len(urls) * 3, 15)
        notes.append("APK ichida URL stringlar topildi.")

    if ips:
        score += min(len(ips) * 4, 16)
        notes.append("APK ichida IP manzillar topildi.")

    keyword_hits = []
    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in joined_lower:
            keyword_hits.append(keyword)

    if keyword_hits:
        score += min(len(keyword_hits) * 4, 20)
        notes.append(f"Shubhali keywordlar topildi: {', '.join(sorted(set(keyword_hits)))}")

    if obfuscation_score >= 60:
        score += 15
        notes.append("Kuchli obfuscation ehtimoli bor.")
    elif obfuscation_score >= 30:
        score += 8
        notes.append("Qisman obfuscation belgilari bor.")

    if exported_components_total >= 10:
        score += 10
        notes.append("Exported componentlar soni ko‘p.")
    elif exported_components_total >= 5:
        score += 5
        notes.append("Bir nechta exported component topildi.")

    score = min(score, 100)

    if score >= 75:
        risk_level = "critical"
    elif score >= 50:
        risk_level = "high"
    elif score >= 25:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "dangerous_permissions": dangerous_permissions,
        "uses_accessibility": uses_accessibility,
        "uses_sms": uses_sms,
        "uses_overlay": uses_overlay,
        "notes": notes,
    }


def analyze_apk_file(apk_path: str) -> Dict[str, Any]:
    file_hashes = calculate_file_hashes(apk_path)

    a, d, dx = AnalyzeAPK(apk_path)

    permissions = safe_list(a.get_permissions())
    package_name = a.get_package()
    app_name = a.get_app_name()
    target_sdk = a.get_target_sdk_version()
    min_sdk = a.get_min_sdk_version()
    max_sdk = a.get_max_sdk_version()

    strings = extract_strings(dx)
    urls = detect_urls(strings)
    ips = detect_ips(strings)

    class_names = []
    try:
        class_names = [c.get_name() for c in d.get_classes()]
    except Exception:
        pass

    obfuscation_score = detect_obfuscation(class_names)
    exported_components = count_exported_components(a)

    risk_data = calculate_risk(
        permissions=permissions,
        urls=urls,
        ips=ips,
        strings=strings,
        obfuscation_score=obfuscation_score,
        exported_components_total=exported_components["total"],
    )

    return {
        "analysis_type": "apk",
        "file_name": os.path.basename(apk_path),
        "file_extension": get_file_extension(apk_path),
        "file_size": get_file_size(apk_path),
        "app_name": app_name,
        "package_name": package_name,
        "min_sdk": min_sdk,
        "target_sdk": target_sdk,
        "max_sdk": max_sdk,
        "sha256": file_hashes["sha256"],
        "md5": file_hashes["md5"],
        "permissions": permissions,
        "urls": urls[:50],
        "ips": ips[:50],
        "obfuscation_score": obfuscation_score,
        "exported_components": exported_components,
        **risk_data,
    }


def analyze_generic_file(file_path: str) -> Dict[str, Any]:
    file_hashes = calculate_file_hashes(file_path)

    return {
        "analysis_type": "generic_file",
        "file_name": os.path.basename(file_path),
        "file_extension": get_file_extension(file_path),
        "file_size": get_file_size(file_path),
        "sha256": file_hashes["sha256"],
        "md5": file_hashes["md5"],
        "risk_score": None,
        "risk_level": "unknown",
        "notes": [
            "Bu fayl APK emas.",
            "Hozircha bu turdagi fayl uchun faqat umumiy metadata ko‘rsatiladi."
        ],
    }


def analyze_file(file_path: str) -> Dict[str, Any]:
    extension = get_file_extension(file_path)

    if extension == ".apk":
        return analyze_apk_file(file_path)

    return analyze_generic_file(file_path)
