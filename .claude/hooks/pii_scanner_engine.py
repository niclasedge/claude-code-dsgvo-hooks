"""
Shared PII Scanner Engine
===========================
Zentrale PII-Erkennung fuer alle DSGVO-Hooks.

Tier 1: Regex (strukturierte PII, <1ms)
Tier 2: Keyword-Kontext (Credentials, Connection Strings, API Keys, <5ms)
Tier 3: GLiNER NLP (Personennamen, Adressen, Organisationen, ~50-200ms)

Verwendung:
    from pii_scanner_engine import PIIScanner
    scanner = PIIScanner()
    findings = scanner.scan("Text mit IBAN DE89 3704 0044 0532 0130 00")
    # -> ["IBAN"]
    findings = scanner.scan("Max Mustermann wohnt in Berlin", tier=3)
    # -> ["Adresse", "Person"]
"""
from __future__ import annotations

import re


class PIIScanner:
    """Zentrale PII-Erkennung fuer alle DSGVO-Hooks."""

    # ─── Tier 3: GLiNER NLP (lazy loaded) ──────────────────

    _gliner_model = None
    _gliner_available: bool | None = None

    # GLiNER Labels → interne Kategorien
    _GLINER_LABELS = ["person", "organization", "address"]
    _GLINER_LABEL_MAP = {
        "person": "Person",
        "organization": "Organisation",
        "address": "Adresse",
    }
    _GLINER_SCORE_THRESHOLD = 0.5

    # ─── Tier 1: Strukturierte PII-Patterns ──────────────

    PATTERNS: dict[str, re.Pattern] = {
        "IBAN": re.compile(
            r"\b[A-Za-z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b"
        ),
        "Telefon": re.compile(
            r"(?:\+49|0049|\b0)[/\s\-]?[1-9][\s\-\(\)/0-9]{5,15}"
        ),
        "Geburtsdatum": re.compile(
            r"\b(0[1-9]|[12]\d|3[01])[.\-/](0[1-9]|1[0-2])[.\-/](19|20)\d{2}\b"
        ),
        "SVN": re.compile(
            r"\b\d{2}[A-Z]\d{6}[A-Z]\d{3}\b"
        ),
        "Email": re.compile(
            r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
        ),
        "IPv4_extern": re.compile(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
        ),
    }

    # ─── Tier 1: Safe-Patterns (False-Positive Filter) ───

    SAFE_EMAIL_PATTERNS = [
        re.compile(r"@example\.(com|test|org|net)$", re.IGNORECASE),
        re.compile(r"@localhost$", re.IGNORECASE),
        re.compile(r"^noreply@", re.IGNORECASE),
        re.compile(r"^test@test", re.IGNORECASE),
        re.compile(r"^user@example", re.IGNORECASE),
        re.compile(r"^testuser", re.IGNORECASE),
    ]

    SAFE_IBAN_PATTERN = re.compile(r"^[A-Za-z]{2}0{2}\s?0{4}\s?0{4}\s?0{4}\s?0{4}")

    PRIVATE_IP_PATTERNS = [
        re.compile(r"^10\."),
        re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
        re.compile(r"^192\.168\."),
        re.compile(r"^127\."),
        re.compile(r"^0\.0\.0\.0$"),
    ]

    # ─── Tier 2: Keyword-Kontext ─────────────────────────

    CREDENTIAL_PATTERNS = [
        re.compile(
            r"(?i)(password|passwort|kennwort|passwd|secret|token|api.?key)"
            r"\s*[:=]\s*\S+"
        ),
    ]

    CONNECTION_STRING_PATTERNS = [
        re.compile(r"(?i)(postgres|mysql|mongodb|redis|amqp)://\S+"),
    ]

    API_KEY_PATTERNS = [
        re.compile(r"sk-[a-zA-Z0-9]{20,}"),
        re.compile(r"AKIA[A-Z0-9]{16}"),
        re.compile(r"ghp_[a-zA-Z0-9]{30,}"),
        re.compile(r"gho_[a-zA-Z0-9]{36}"),
        re.compile(r"xoxb-[a-zA-Z0-9\-]+"),
    ]

    def scan(self, text: str, tier: int = 2) -> list[str]:
        """Scannt Text auf PII. Gibt Liste gefundener Kategorien zurueck."""
        result = self.scan_detailed(text, tier=tier)
        return result["categories"]

    def scan_detailed(self, text: str, tier: int = 2) -> dict:
        """Scannt Text auf PII. Gibt Kategorien und NLP-Entities zurueck.

        Returns:
            {"categories": ["Email", "Person", ...],
             "entities": [{"text": "Max Mustermann", "label": "Person", "score": 0.88}, ...]}
        """
        if not text:
            return {"categories": [], "entities": []}

        findings: set[str] = set()
        entities: list[dict] = []

        # ── Tier 1: Regex ────────────────────────────────
        for category, pattern in self.PATTERNS.items():
            matches = pattern.findall(text)
            if not matches:
                continue

            if category == "Email":
                real = [m for m in matches if not self._is_safe_email(m)]
                if real:
                    findings.add(category)
            elif category == "IBAN":
                real = [m for m in matches if not self.SAFE_IBAN_PATTERN.match(m)]
                if real:
                    findings.add(category)
            elif category == "IPv4_extern":
                real = [m for m in matches if not self._is_private_ip(m)]
                if real:
                    findings.add(category)
            else:
                findings.add(category)

        # ── Tier 2: Keyword-Kontext ──────────────────────
        if tier >= 2:
            for p in self.CREDENTIAL_PATTERNS:
                if p.search(text):
                    findings.add("Credentials")
                    break

            for p in self.CONNECTION_STRING_PATTERNS:
                if p.search(text):
                    findings.add("Connection_String")
                    break

            for p in self.API_KEY_PATTERNS:
                if p.search(text):
                    findings.add("API_Key")
                    break

        # ── Tier 3: GLiNER NLP ───────────────────────────
        if tier >= 3:
            nlp_entities = self._scan_gliner(text)
            for ent in nlp_entities:
                findings.add(ent["label"])
                entities.append(ent)

        return {"categories": sorted(findings), "entities": entities}

    def _is_safe_email(self, email: str) -> bool:
        """Prueft ob eine Email ein bekannter False-Positive ist."""
        return any(p.search(email) for p in self.SAFE_EMAIL_PATTERNS)

    def _is_private_ip(self, ip: str) -> bool:
        """Prueft ob eine IP privat/intern ist."""
        return any(p.match(ip) for p in self.PRIVATE_IP_PATTERNS)

    # ─── Tier 3: GLiNER ────────────────────────────────────

    @classmethod
    def _load_gliner(cls) -> bool:
        """Laedt GLiNER Modell (lazy, singleton). Gibt True zurueck wenn verfuegbar."""
        if cls._gliner_available is not None:
            return cls._gliner_available
        try:
            from gliner import GLiNER
            cls._gliner_model = GLiNER.from_pretrained(
                "knowledgator/gliner-pii-base-v1.0"
            )
            cls._gliner_available = True
        except (ImportError, Exception):
            cls._gliner_available = False
        return cls._gliner_available

    def _scan_gliner(self, text: str) -> list[dict]:
        """Scannt Text mit GLiNER NLP. Gibt Entities zurueck."""
        if not self._load_gliner() or not text.strip():
            return []

        try:
            raw_entities = self._gliner_model.predict_entities(
                text, self._GLINER_LABELS
            )
        except Exception:
            return []

        result = []
        for ent in raw_entities:
            if ent.get("score", 0) < self._GLINER_SCORE_THRESHOLD:
                continue
            label = self._GLINER_LABEL_MAP.get(ent["label"], ent["label"])
            result.append({
                "text": ent["text"],
                "label": label,
                "score": round(ent["score"], 2),
            })
        return result
