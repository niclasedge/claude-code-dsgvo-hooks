#!/usr/bin/env python3
"""
DSGVO Mock-Daten-Generator (Presidio + GLiNER)

Abhaengigkeiten (Extra "mock-data" in pyproject.toml):
  presidio-analyzer, presidio-anonymizer, spacy, de-core-news-lg, gliner
  → uv run --extra mock-data vom Projektverzeichnis aus ausfuehren
====================================================
Erstellt anonymisierte .clean-Versionen von PII-haltigen Dateien.
Nutzt Microsoft Presidio fuer robuste PII-Erkennung und Anonymisierung,
mit GLiNER als zusaetzlichem Custom Recognizer fuer Zero-Shot NER.

Unterstuetzte Formate:
  - CSV/TSV: Ersetzt PII-Felder durch Dummy-Daten
  - JSON: Ersetzt PII-Werte durch Dummy-Daten
  - Text/Config/Source: Ersetzt PII via Presidio + GLiNER NLP

Verwendung:
  uv run --extra mock-data .claude/tools/generate_mock_data.py                          # Interaktives Menu
  uv run --extra mock-data .claude/tools/generate_mock_data.py --dry <datei>            # PII-Fundstellen anzeigen
  uv run --extra mock-data .claude/tools/generate_mock_data.py <datei>                  # Erstellt .clean-Version
  uv run --extra mock-data .claude/tools/generate_mock_data.py --action deep-scan       # Deep Scan ohne Menu
  uv run --extra mock-data .claude/tools/generate_mock_data.py --action protect-data    # Datendateien schuetzen
  uv run --extra mock-data .claude/tools/generate_mock_data.py --action protect-source  # Source-Code schuetzen
  uv run --extra mock-data .claude/tools/generate_mock_data.py --action regenerate-all  # Alle .clean regenerieren
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from presidio_analyzer import (
    AnalyzerEngine,
    PatternRecognizer,
    Pattern,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import SpacyNlpEngine, NlpArtifacts
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


# ─── Mock-Daten ──────────────────────────────────────

MOCK_NAMES = [
    "Anna Beispiel", "Peter Musterfall", "Erika Musterfrau",
    "Test Testperson", "Demo Benutzer", "Probe Mitarbeiter",
    "Muster Kunde", "Dummy Datensatz",
]
MOCK_EMAILS = [f"testuser.{i:03d}@example.test" for i in range(1, 20)]
MOCK_PHONES = [f"+49 000 {i:07d}" for i in range(1, 20)]
MOCK_IBANS = [f"DE{11+i} 1111 2222 3333 4444 {55+i}" for i in range(20)]
MOCK_DATES = ["01.01.2000", "02.02.2001", "03.03.2002", "04.04.2003"]
MOCK_ADDRESSES = [
    "Musterstrasse 1, 10000 Musterstadt",
    "Beispielweg 42, 20000 Beispielstadt",
    "Testgasse 7, 30000 Teststadt",
    "Demoallee 99, 40000 Demostadt",
]
MOCK_ORGS = ["Muster GmbH", "Beispiel AG", "Test Corp.", "Demo Verein e.V."]
MOCK_CREDENTIALS = ["***REDACTED***", "***REMOVED***", "***MOCK_SECRET***"]
MOCK_CONNECTION_STRINGS = [
    "postgres://user:***@localhost:5432/testdb",
    "mysql://user:***@localhost:3306/testdb",
]
MOCK_API_KEYS = ["sk-MOCK0000000000000000", "AKIAMOCKMOCKMOKMOCK"]
MOCK_URLS = ["https://example.test"]
MOCK_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

# Counter fuer eindeutige Mock-Daten
_mock_counters: dict[str, int] = {}


def _next_mock(category: str, pool: list[str]) -> str:
    idx = _mock_counters.get(category, 0)
    _mock_counters[category] = idx + 1
    return pool[idx % len(pool)]


def _reset_counters() -> None:
    _mock_counters.clear()


# ─── Mock-Daten Mapping: Entity-Type → Pool ─────────

ENTITY_MOCK_MAP: dict[str, list[str]] = {
    "PERSON": MOCK_NAMES,
    "EMAIL_ADDRESS": MOCK_EMAILS,
    "PHONE_NUMBER": MOCK_PHONES,
    "IBAN_CODE": MOCK_IBANS,
    "DATE_TIME": MOCK_DATES,
    "LOCATION": MOCK_ADDRESSES,
    "NRP": MOCK_NAMES,  # Nationality/Religion/Political group
    "ORGANIZATION": MOCK_ORGS,
    "CREDIT_CARD": ["0000-0000-0000-0000"],
    "IP_ADDRESS": MOCK_IPS,
    "URL": MOCK_URLS,
    # Custom entity types
    "CREDENTIAL": MOCK_CREDENTIALS,
    "CONNECTION_STRING": MOCK_CONNECTION_STRINGS,
    "API_KEY": MOCK_API_KEYS,
    "DE_IBAN": MOCK_IBANS,
    "GERMAN_PHONE": MOCK_PHONES,
    "DE_SVN": ["00A000000A000"],
    "DE_DATE": MOCK_DATES,
}


# ─── Custom Recognizers ──────────────────────────────

class CredentialRecognizer(PatternRecognizer):
    """Erkennt Credentials wie password=X, token=X etc."""

    PATTERNS = [
        Pattern(
            "credential_assignment",
            r"(?i)(password|passwort|kennwort|passwd|secret|token|api.?key)\s*[:=]\s*\S+",
            0.9,
        ),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="CREDENTIAL",
            patterns=self.PATTERNS,
            supported_language="de",
        )


class ConnectionStringRecognizer(PatternRecognizer):
    """Erkennt Connection Strings (postgres://, mysql:// etc.)."""

    PATTERNS = [
        Pattern("conn_string", r"(?i)(postgres|mysql|mongodb|redis|amqp)://\S+", 0.95),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="CONNECTION_STRING",
            patterns=self.PATTERNS,
            supported_language="de",
        )


class ApiKeyRecognizer(PatternRecognizer):
    """Erkennt API Keys (sk-, AKIA, ghp_, etc.)."""

    PATTERNS = [
        Pattern("openai_key", r"sk-[a-zA-Z0-9]{20,}", 0.95),
        Pattern("aws_key", r"AKIA[A-Z0-9]{16}", 0.95),
        Pattern("github_pat", r"ghp_[a-zA-Z0-9]{30,}", 0.95),
        Pattern("github_oauth", r"gho_[a-zA-Z0-9]{36}", 0.95),
        Pattern("slack_token", r"xoxb-[a-zA-Z0-9\-]+", 0.90),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="API_KEY",
            patterns=self.PATTERNS,
            supported_language="de",
        )


class GermanIbanRecognizer(PatternRecognizer):
    """Erkennt deutsche IBANs (DE + 20 Ziffern)."""

    PATTERNS = [
        Pattern(
            "de_iban",
            r"\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}\b",
            0.95,
        ),
    ]

    SAFE_IBAN = re.compile(r"^[A-Z]{2}0{2}\s?0{4}\s?0{4}\s?0{4}\s?0{4}")

    def __init__(self) -> None:
        super().__init__(
            supported_entity="DE_IBAN",
            patterns=self.PATTERNS,
            supported_language="de",
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        if self.SAFE_IBAN.match(pattern_text):
            return False
        return True


class GermanPhoneRecognizer(PatternRecognizer):
    """Erkennt deutsche Telefonnummern."""

    PATTERNS = [
        Pattern(
            "de_phone",
            r"(?:\+49|0049|0)\s?[1-9][\d\s\-/()]{5,13}\d",
            0.85,
        ),
    ]

    # Datum-aehnliche Patterns ausschliessen (z.B. 024-01-15 aus 2024-01-15)
    _DATE_LIKE = re.compile(r"^0?\d{2,3}[\-/]\d{2}[\-/]\d{2,4}$")

    def __init__(self) -> None:
        super().__init__(
            supported_entity="GERMAN_PHONE",
            patterns=self.PATTERNS,
            supported_language="de",
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        """Filtert Datum-aehnliche Matches."""
        cleaned = pattern_text.strip()
        if self._DATE_LIKE.match(cleaned):
            return False
        # Reine Ziffern ohne Trennzeichen und zu kurz → kein Telefon
        digits_only = re.sub(r"[^\d]", "", cleaned)
        if len(digits_only) < 7:
            return False
        return True


class GermanSvnRecognizer(PatternRecognizer):
    """Erkennt deutsche Sozialversicherungsnummern."""

    PATTERNS = [
        Pattern("de_svn", r"\b\d{2}[A-Z]\d{6}[A-Z]\d{3}\b", 0.90),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="DE_SVN",
            patterns=self.PATTERNS,
            supported_language="de",
        )


class GermanDateRecognizer(PatternRecognizer):
    """Erkennt deutsche Datumsformate (TT.MM.JJJJ)."""

    PATTERNS = [
        Pattern(
            "de_date",
            r"\b(0[1-9]|[12]\d|3[01])[.\-/](0[1-9]|1[0-2])[.\-/](19|20)\d{2}\b",
            0.85,
        ),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="DE_DATE",
            patterns=self.PATTERNS,
            supported_language="de",
        )


class GlinerRecognizer(PatternRecognizer):
    """GLiNER Zero-Shot NER als Presidio Custom Recognizer."""

    _model = None
    _available: bool | None = None

    GLINER_LABELS = ["person", "organization", "address"]
    LABEL_TO_ENTITY = {
        "person": "PERSON",
        "organization": "ORGANIZATION",
        "address": "LOCATION",
    }
    SCORE_THRESHOLD = 0.7

    def __init__(self) -> None:
        super().__init__(
            supported_entity="PERSON",
            patterns=[Pattern("dummy", r"GLINER_DUMMY_NEVER_MATCH_12345", 0.0)],
            supported_language="de",
        )

    @classmethod
    def _load_model(cls) -> bool:
        if cls._available is not None:
            return cls._available
        try:
            from gliner import GLiNER
            cls._model = GLiNER.from_pretrained("knowledgator/gliner-pii-base-v1.0")
            cls._available = True
        except (ImportError, Exception):
            cls._available = False
        return cls._available

    def analyze(
        self, text: str, entities: list[str], nlp_artifacts: NlpArtifacts = None
    ) -> list[RecognizerResult]:
        if not self._load_model() or not text.strip():
            return []

        try:
            raw = self._model.predict_entities(text, self.GLINER_LABELS)
        except Exception:
            return []

        results = []
        for ent in raw:
            if ent.get("score", 0) < self.SCORE_THRESHOLD:
                continue
            entity_type = self.LABEL_TO_ENTITY.get(ent["label"], "PERSON")
            if entity_type not in entities and "All" not in entities:
                continue
            results.append(
                RecognizerResult(
                    entity_type=entity_type,
                    start=ent["start"],
                    end=ent["end"],
                    score=ent["score"],
                )
            )
        return results


# ─── Presidio Engine Setup ────────────────────────────

_analyzer: AnalyzerEngine | None = None
_anonymizer: AnonymizerEngine | None = None


def _ensure_spacy_model(model_name: str = "de_core_news_lg") -> None:
    """Stellt sicher dass das spaCy-Modell installiert ist, laedt es bei Bedarf."""
    import spacy
    try:
        spacy.load(model_name)
    except OSError:
        print(f"  spaCy-Modell '{model_name}' nicht gefunden — wird heruntergeladen...")
        spacy.cli.download(model_name)
        print(f"  Modell '{model_name}' installiert.")


def _get_analyzer() -> AnalyzerEngine:
    """Laedt Presidio Analyzer mit allen Custom Recognizers (Singleton)."""
    global _analyzer
    if _analyzer is not None:
        return _analyzer

    _ensure_spacy_model("de_core_news_lg")
    nlp_engine = SpacyNlpEngine(
        models=[{"lang_code": "de", "model_name": "de_core_news_lg"}]
    )
    _analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine, supported_languages=["de"]
    )

    # Custom Recognizers registrieren
    _analyzer.registry.add_recognizer(CredentialRecognizer())
    _analyzer.registry.add_recognizer(ConnectionStringRecognizer())
    _analyzer.registry.add_recognizer(ApiKeyRecognizer())
    _analyzer.registry.add_recognizer(GermanIbanRecognizer())
    _analyzer.registry.add_recognizer(GermanPhoneRecognizer())
    _analyzer.registry.add_recognizer(GermanSvnRecognizer())
    _analyzer.registry.add_recognizer(GermanDateRecognizer())
    _analyzer.registry.add_recognizer(GlinerRecognizer())

    return _analyzer


def _get_anonymizer() -> AnonymizerEngine:
    global _anonymizer
    if _anonymizer is None:
        _anonymizer = AnonymizerEngine()
    return _anonymizer


# ─── Anonymisierung mit Mock-Daten ────────────────────

_FALSE_POSITIVE_RE = re.compile(
    r"^[\s|+\-=_:.*#/\\>{}<\[\]]+$"  # Markdown-Tabellen, Trennzeichen, Formatierung
    r"|^[a-z0-9]+(?:-[a-z0-9]+){3,}$"  # URL-Slugs (lowercase-mit-bindestrichen)
    r"|^https?://"  # URLs
)

# Python/Code Keywords und Patterns die keine PII sind
_CODE_KEYWORDS = {
    "class", "def", "import", "from", "return", "if", "else", "elif", "for",
    "while", "try", "except", "finally", "with", "as", "yield", "raise",
    "pass", "break", "continue", "lambda", "assert", "global", "nonlocal",
    "async", "await", "in", "is", "not", "and", "or", "true", "false", "none",
    "self", "cls", "type", "dict", "list", "set", "tuple", "str", "int",
    "float", "bool", "bytes", "object", "super", "print", "len", "range",
}

# Woerter die haeufig faelschlich als PERSON erkannt werden
_FALSE_PERSON_WORDS = {
    "hook", "hooks", "leverage", "periodically", "establish", "manually",
    "configure", "dict", "exit", "error", "debug", "test", "check",
    "kombiniert", "erlauben", "claude", "bash", "prompt", "file",
    "env", "hex", "cat", "guard", "dump", "split", "merge",
    "rehberger", "contradicting", "read", "write", "edit", "delete",
}

# Woerter die haeufig faelschlich als ORGANIZATION erkannt werden
_FALSE_ORG_WORDS = {
    "login", "download", "upload", "security", "class", "import",
    "pytest", "developers", "edge", "gateway", "actionable",
    "tdd", "json", "hook", "quoting", "printenv",
    "festnetz", "mobilfunk", "organisation", "piiscanner",
}

# Einzelwoerter die keine echte LOCATION sind (generische Labels)
_FALSE_LOCATION_WORDS = {
    "adresse", "buero", "organisation", "filetype",
}

# Mehrwort-Phrasen die keine echte PII sind (product names, tech terms)
_FALSE_POSITIVE_PHRASES = {
    "claude code", "actionable insights", "hook-tests", "json-dict",
    "projekt-root", "edge cases",
}

# Regex fuer Code-Identifier (CamelCase, UPPER_SNAKE, snake_case, @decorator)
_CODE_IDENTIFIER_RE = re.compile(
    r"^@\w+"  # Decorator
    r"|^[A-Z][a-z]+(?:[A-Z][a-z]+){1,}$"  # CamelCase (TestBlockPiiFiles)
    r"|^[A-Z]{2,}[a-z]+(?:[A-Z][a-z]+)*$"  # AcronymCamel (PIIScanner, HTMLParser)
    r"|^[A-Z][A-Z0-9_]{2,}$"  # UPPER_SNAKE_CASE (TESTFILES_DIR)
    r"|^[A-Za-z]+_[A-Za-z_]+$"  # Mixed_Case_Identifier (Connection_String)
    r"|^[a-z_][a-z0-9_]*$"  # snake_case (result_stdout)
    r"|^[a-z]+[A-Z][a-zA-Z]*$"  # lowerCamelCase (filePath, fileName)
    r"|^[a-z_][a-z0-9_.]*\.[a-z_]"  # dotted.path (result.stdout.strip)
    r"|^\w+Error$"  # Exception names (JSONDecodeError)
    r"|^\w+Exception$"  # Exception names
    r"|^\w+Warning$"  # Warning names
)

# Entity-Typen die keine echte PII sind
_IGNORED_ENTITY_TYPES = {"URL", "DATE_TIME"}

# Prioritaet fuer Deduplizierung bei Ueberlappung (hoeher = bevorzugt)
_ENTITY_PRIORITY = {
    "DE_IBAN": 10, "IBAN_CODE": 9,
    "CREDENTIAL": 10, "API_KEY": 10, "CONNECTION_STRING": 10,
    "EMAIL_ADDRESS": 10, "PERSON": 8, "ORGANIZATION": 7,
    "LOCATION": 6, "GERMAN_PHONE": 5, "DE_SVN": 10,
    "DE_DATE": 7,
}


def _is_false_positive(text: str, result: RecognizerResult) -> bool:
    """Filtert offensichtliche False Positives."""
    snippet = text[result.start:result.end]
    snippet_stripped = snippet.strip()
    snippet_lower = snippet_stripped.lower()

    if _FALSE_POSITIVE_RE.match(snippet_stripped):
        return True

    # Kurze Snippets (<=3 Zeichen) sind selten echte PERSON/ORGANIZATION/LOCATION
    if result.entity_type in ("PERSON", "ORGANIZATION", "LOCATION"):
        alpha_chars = sum(1 for c in snippet if c.isalpha())
        if alpha_chars <= 3:
            return True

    # Einzelne Woerter ohne Grossbuchstaben
    if result.entity_type in ("PERSON", "ORGANIZATION") and " " not in snippet_stripped:
        if snippet_stripped.islower() or not any(c.isalpha() for c in snippet_stripped):
            return True

    # --- Code-spezifische Filter ---

    # Python/Code Keywords
    if snippet_lower in _CODE_KEYWORDS:
        return True

    # Code-Identifier (CamelCase, UPPER_SNAKE, snake_case, decorators, dotted paths)
    if result.entity_type in ("PERSON", "ORGANIZATION", "LOCATION"):
        if _CODE_IDENTIFIER_RE.match(snippet_stripped):
            return True

    # Bekannte False-Positive-Woerter
    if result.entity_type == "PERSON" and snippet_lower in _FALSE_PERSON_WORDS:
        return True
    if result.entity_type == "ORGANIZATION" and snippet_lower in _FALSE_ORG_WORDS:
        return True

    # Bekannte False-Positive-Phrasen (Produktnamen, Tech-Terme)
    if snippet_lower in _FALSE_POSITIVE_PHRASES:
        return True

    # Einzelwoerter die keine echte LOCATION sind
    if result.entity_type == "LOCATION" and snippet_lower in _FALSE_LOCATION_WORDS:
        return True

    # Snippet enthaelt Code-Syntax (Klammern, Punkte, Unterstriche, Gleichheitszeichen)
    if result.entity_type in ("PERSON", "ORGANIZATION", "LOCATION"):
        code_chars = sum(1 for c in snippet_stripped if c in "()[]{}=_.<>@/\\;:#")
        if code_chars > 0 and code_chars / max(len(snippet_stripped), 1) > 0.1:
            return True

    # Snippet enthaelt Dateiendung (.csv, .py, .json etc.) → Shell-Befehl, kein Name
    if result.entity_type == "PERSON":
        if re.search(r"\.\w{1,5}\b", snippet_stripped) and " " in snippet_stripped:
            return True

    # Zeile beginnt mit typischem Code-Prefix → alles in der Zeile ist verdaechtig
    line_start = text.rfind("\n", 0, result.start) + 1
    line_end = text.find("\n", result.end)
    if line_end == -1:
        line_end = len(text)
    full_line = text[line_start:line_end].lstrip()
    if result.entity_type in ("PERSON", "ORGANIZATION", "LOCATION"):
        if re.match(r"^(class |def |import |from |except |raise |return |@|#|//|/\*|\*|\"\"\"|\'{3})", full_line):
            return True

    # Snippet beginnt mit "class " oder "def " (z.B. "class TestFoo")
    if snippet_stripped.startswith(("class ", "def ")):
        return True

    # Einzelnes Wort in ALL-CAPS ohne Leerzeichen → wahrscheinlich Konstante/Enum
    if result.entity_type in ("PERSON", "ORGANIZATION") and " " not in snippet_stripped:
        if snippet_stripped.isupper() and snippet_stripped.isalpha():
            return True

    # Snippet enthaelt Text der wie ein englischer Satzanfang aussieht (Imperativ)
    # z.B. "Manually configure...", "Periodically...", "Establish..."
    if result.entity_type == "PERSON" and " " in snippet_stripped:
        words = snippet_stripped.split()
        if len(words) >= 2 and words[0][0].isupper() and all(w[0].islower() for w in words[1:] if w):
            # Pruefen ob erster Wort ein englisches Verb sein koennte (endet auf typische Suffixe)
            first = words[0].lower()
            if first.endswith(("ly", "ally", "ically", "ously", "ably", "ibly")):
                return True
            if first.endswith(("ing", "ize", "ise", "ate", "ect", "ure", "ish")):
                return True

    # Deutsche/technische Komposita mit Bindestrich (z.B. Gateway-Konfiguration, Hook-Tests)
    if result.entity_type in ("PERSON", "LOCATION", "ORGANIZATION") and "-" in snippet_stripped:
        parts = snippet_stripped.split("-")
        # Adress-Bestandteile nicht filtern
        address_parts = {"strasse", "str", "platz", "weg", "allee", "gasse", "ring", "damm"}
        if any(p.lower() in address_parts for p in parts):
            return False  # Ist wahrscheinlich eine echte Adresse
        # Technische Komposita: Wort-Wort mit Grossbuchstaben
        if len(parts) >= 2 and all(p[0:1].isupper() for p in parts if p):
            return True

    # Deutsche Komposita ohne Bindestrich (z.B. Systemzugangsdaten, Kontoverwaltung)
    _KOMPOSITUM_SUFFIXE = (
        "daten", "verwaltung", "konfiguration", "einstellungen", "verzeichnis",
        "informationen", "beschreibung", "verarbeitung", "zusammenfassung",
        "protokoll", "anleitung", "hinweise", "bedingungen", "anforderungen",
        "dateien", "skripte", "kommandos",
    )
    if result.entity_type in ("LOCATION", "ORGANIZATION", "PERSON") and " " not in snippet_stripped:
        lower = snippet_stripped.lower()
        if any(lower.endswith(s) for s in _KOMPOSITUM_SUFFIXE) and len(snippet_stripped) > 8:
            return True

    return False


def _deduplicate_results(results: list[RecognizerResult]) -> list[RecognizerResult]:
    """Entfernt ueberlappende Erkennungen, behaelt die mit hoechster Prioritaet/Score."""
    if not results:
        return results
    # Sortiere nach Start, dann nach Prioritaet (absteigend)
    sorted_results = sorted(
        results,
        key=lambda r: (r.start, -_ENTITY_PRIORITY.get(r.entity_type, 0), -r.score),
    )
    kept: list[RecognizerResult] = []
    for r in sorted_results:
        # Pruefen ob dieses Ergebnis mit einem bereits behaltenen ueberlappt
        overlaps = False
        for k in kept:
            # Ueberlappung: nicht (r endet vor k oder r startet nach k)
            if not (r.end <= k.start or r.start >= k.end):
                overlaps = True
                break
        if not overlaps:
            kept.append(r)
    return kept


def anonymize_text_presidio(text: str) -> tuple[str, list[dict]]:
    """Analysiert und anonymisiert Text mit Presidio. Gibt (anonymized_text, findings) zurueck."""
    if not text.strip():
        return text, []

    analyzer = _get_analyzer()
    results = analyzer.analyze(text=text, language="de", score_threshold=0.6)

    # Ignorierte Typen, False-Positive-Filter, Deduplizierung
    results = [r for r in results
               if r.entity_type not in _IGNORED_ENTITY_TYPES
               and not _is_false_positive(text, r)]
    results = _deduplicate_results(results)

    if not results:
        return text, []

    # Anonymisierung mit Custom Operators (Mock-Daten)
    anonymizer = _get_anonymizer()

    # Operator-Config: Jeder Entity-Type bekommt seine Mock-Daten
    operators: dict[str, OperatorConfig] = {}
    mock_mapping: dict[str, str] = {}  # entity_type -> mock_value
    for r in results:
        if r.entity_type not in operators:
            pool = ENTITY_MOCK_MAP.get(r.entity_type)
            if pool:
                mock_val = _next_mock(r.entity_type, pool)
                operators[r.entity_type] = OperatorConfig(
                    "replace", {"new_value": mock_val}
                )
                mock_mapping[r.entity_type] = mock_val
            else:
                placeholder = f"<{r.entity_type}>"
                operators[r.entity_type] = OperatorConfig(
                    "replace", {"new_value": placeholder}
                )
                mock_mapping[r.entity_type] = placeholder

    # Findings fuer Report (mit Ersetzungswert)
    findings = []
    for r in sorted(results, key=lambda x: x.start):
        snippet = text[r.start:r.end]
        findings.append({
            "typ": r.entity_type,
            "wert": snippet,
            "ersetzt_durch": mock_mapping.get(r.entity_type, "?"),
            "score": round(r.score, 2),
            "start": r.start,
            "end": r.end,
        })

    anon_result = anonymizer.anonymize(
        text=text, analyzer_results=results, operators=operators
    )
    return anon_result.text, findings


# ─── Dateitypen ───────────────────────────────────────

TEXT_EXTENSIONS = {".txt", ".log", ".ini", ".cfg", ".yaml", ".yml"}
SOURCE_CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".rb", ".java",
    ".c", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt",
    ".md", ".rst", ".html", ".css", ".sh",
    ".svelte", ".vue", ".astro",
}
SCANNABLE_EXTENSIONS = {".csv", ".tsv", ".json", ".xml"} | TEXT_EXTENSIONS | SOURCE_CODE_EXTENSIONS
ALL_PII_EXTENSIONS = {
    ".csv", ".tsv", ".xlsx", ".xls", ".xlsm",
    ".vcf", ".ldif", ".sql",
    ".db", ".sqlite", ".sqlite3",
}
NAME_FIELDS = {"name", "vorname", "nachname", "mitarbeiter", "kontakt", "bewerber"}
PII_NAME_INDICATORS = [
    "customer", "kunden", "mitarbeiter", "employee", "personal",
    "kontakt", "contact", "patient", "bewerber", "applicant",
    "user", "nutzer", "person", "gehalt", "salary", "lohn",
    "adress", "address", "telefon", "phone", "email",
    "sozialversicherung", "insurance", "krankenkasse",
    "backup", "export", "dump", "report",
]
SAFE_PATTERNS = [".clean", "mock_", "fixture", "example", "sample", "template"]


def _is_safe_file(path: Path) -> bool:
    lower = path.name.lower()
    return any(p in lower for p in SAFE_PATTERNS)


def _text_has_pii(path: Path) -> bool:
    """Prueft Textdatei mit Presidio auf PII."""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")[:5000]
        analyzer = _get_analyzer()
        results = analyzer.analyze(text=content, language="de", score_threshold=0.6)
        # Filter false positives
        real = [r for r in results if r.entity_type not in ("URL",)]
        return len(real) > 0
    except Exception:
        return False


def _needs_clean(path: Path, include_source: bool = False) -> bool:
    if _is_safe_file(path):
        return False
    ext = path.suffix.lower()
    if ext in SOURCE_CODE_EXTENSIONS:
        if not include_source:
            return False
        return _text_has_pii(path)
    if ext in ALL_PII_EXTENSIONS:
        return True
    if ext in TEXT_EXTENSIONS:
        return _text_has_pii(path)
    if ext in (".json", ".xml"):
        lower = path.name.lower()
        return any(ind in lower for ind in PII_NAME_INDICATORS)
    return False


def _has_clean_version(path: Path) -> bool:
    return Path(f"{path}.clean").exists()


# ─── Verarbeitung: Text ──────────────────────────────

def process_text(input_path: Path, output_path: Path) -> None:
    """Anonymisiert Textdateien mit Presidio."""
    _reset_counters()
    lines = input_path.read_text(encoding="utf-8", errors="replace").splitlines()
    new_lines: list[str] = []

    for line in lines:
        if not line.strip():
            new_lines.append(line)
            continue
        anon_line, _ = anonymize_text_presidio(line)
        new_lines.append(anon_line)

    output_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


# ─── Verarbeitung: CSV ───────────────────────────────

def process_csv(input_path: Path, output_path: Path, delimiter: str = ",") -> None:
    """Anonymisiert CSV/TSV mit Presidio."""
    _reset_counters()

    with open(input_path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    new_rows = []
    for row in rows:
        new_row = {}
        for col, val in row.items():
            if not val:
                new_row[col] = val
                continue
            anon_val, _ = anonymize_text_presidio(val)
            new_row[col] = anon_val
        new_rows.append(new_row)

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter=delimiter)
        writer.writeheader()
        writer.writerows(new_rows)


# ─── Verarbeitung: JSON ──────────────────────────────

def process_json(input_path: Path, output_path: Path) -> None:
    """Anonymisiert JSON mit Presidio."""
    _reset_counters()

    with open(input_path, encoding="utf-8") as f:
        data = json.load(f)

    anonymized = _anonymize_json_obj(data)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(anonymized, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _anonymize_json_obj(obj: object) -> object:
    if isinstance(obj, dict):
        return {k: _anonymize_json_obj(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_anonymize_json_obj(item) for item in obj]
    elif isinstance(obj, str):
        anon, _ = anonymize_text_presidio(obj)
        return anon
    else:
        return obj


# ─── Dry-Run ─────────────────────────────────────────

def dry_run_text(input_path: Path) -> list[dict]:
    """Scannt Textdatei mit Presidio nach PII."""
    findings: list[dict] = []
    try:
        lines = input_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as exc:
        findings.append({"zeile": 0, "feld": "-", "typ": "Fehler", "wert": str(exc)})
        return findings

    for line_nr, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        _, line_findings = anonymize_text_presidio(line)
        for f in line_findings:
            findings.append({
                "zeile": line_nr,
                "feld": "-",
                "typ": f"{f['typ']} ({f['score']:.0%})",
                "wert": f["wert"],
                "ersetzt_durch": f.get("ersetzt_durch", ""),
            })
    return findings


def dry_run_csv(input_path: Path, delimiter: str = ",") -> list[dict]:
    """Scannt CSV/TSV mit Presidio nach PII."""
    findings: list[dict] = []

    with open(input_path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        rows = list(reader)

    for row_idx, row in enumerate(rows, start=2):
        for col, val in row.items():
            if not val:
                continue
            _, cell_findings = anonymize_text_presidio(val)
            for f in cell_findings:
                findings.append({
                    "zeile": row_idx,
                    "feld": col,
                    "typ": f"{f['typ']} ({f['score']:.0%})",
                    "wert": f["wert"],
                    "ersetzt_durch": f.get("ersetzt_durch", ""),
                })
    return findings


def dry_run_json(input_path: Path) -> list[dict]:
    """Scannt JSON mit Presidio nach PII."""
    findings: list[dict] = []

    with open(input_path, encoding="utf-8") as f:
        data = json.load(f)

    def scan_obj(obj: object, path: str = "") -> None:
        if isinstance(obj, dict):
            for key, val in obj.items():
                key_path = f"{path}.{key}" if path else key
                if isinstance(val, str):
                    _, val_findings = anonymize_text_presidio(val)
                    for f in val_findings:
                        findings.append({
                            "feld": key_path,
                            "typ": f"{f['typ']} ({f['score']:.0%})",
                            "wert": f["wert"],
                            "ersetzt_durch": f.get("ersetzt_durch", ""),
                        })
                else:
                    scan_obj(val, key_path)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                scan_obj(item, f"{path}[{idx}]")

    scan_obj(data)
    return findings


def print_dry_report(findings: list[dict], input_path: Path, show_replacement: bool = True) -> None:
    """Gibt Dry-Run-Report auf stdout aus."""
    print(f"  PII-Scan (Presidio v2): {input_path}")
    print(f"  {'=' * 68}")

    if not findings:
        print("  Keine PII-Fundstellen gefunden.")
        return

    for f in findings:
        ersetzt = f.get("ersetzt_durch", "")
        arrow = f"  ->  {ersetzt}" if show_replacement and ersetzt else ""
        if "zeile" in f:
            print(f"  Zeile {f['zeile']:3d} | {f['typ']:<28s} | {f['wert']}{arrow}")
        else:
            print(f"  Feld '{f['feld']}' | {f['typ']:<28s} | {f['wert']}{arrow}")

    print(f"  {'=' * 68}")
    print(f"  {len(findings)} PII-Fundstellen gefunden.")


def dry_run_single(input_path: Path) -> int:
    ext = input_path.suffix.lower()
    if ext in (".csv",):
        findings = dry_run_csv(input_path, delimiter=",")
    elif ext in (".tsv",):
        findings = dry_run_csv(input_path, delimiter="\t")
    elif ext in (".json",):
        findings = dry_run_json(input_path)
    elif ext in TEXT_EXTENSIONS or ext in SOURCE_CODE_EXTENSIONS:
        findings = dry_run_text(input_path)
    else:
        print(f"Fehler: Format '{ext}' nicht unterstuetzt.", file=sys.stderr)
        return 1
    print_dry_report(findings, input_path)
    return 0


def process_single(input_path: Path, output_path: Path) -> bool:
    ext = input_path.suffix.lower()
    try:
        if ext in (".csv",):
            process_csv(input_path, output_path, delimiter=",")
        elif ext in (".tsv",):
            process_csv(input_path, output_path, delimiter="\t")
        elif ext in (".json",):
            process_json(input_path, output_path)
        elif ext in TEXT_EXTENSIONS or ext in SOURCE_CODE_EXTENSIONS:
            process_text(input_path, output_path)
        else:
            print(f"  Format '{ext}' nicht unterstuetzt — uebersprungen.")
            return False
        return True
    except Exception as exc:
        print(f"  Fehler: {exc}")
        return False


# ─── Verzeichnis-Scan ─────────────────────────────────

def scan_directory(directory: Path, include_source: bool = False) -> list[dict]:
    results: list[dict] = []

    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        if any(part.startswith(".") for part in path.relative_to(directory).parts):
            continue
        if not _needs_clean(path, include_source=include_source):
            continue

        has_clean = _has_clean_version(path)
        ext = path.suffix.lower()
        can_scan = ext in SCANNABLE_EXTENSIONS
        rel = path.relative_to(directory)

        pii_count = 0
        if can_scan and not has_clean:
            try:
                if ext == ".csv":
                    pii_count = len(dry_run_csv(path, delimiter=","))
                elif ext == ".tsv":
                    pii_count = len(dry_run_csv(path, delimiter="\t"))
                elif ext == ".json":
                    pii_count = len(dry_run_json(path))
                elif ext in TEXT_EXTENSIONS or ext in SOURCE_CODE_EXTENSIONS:
                    pii_count = len(dry_run_text(path))
            except Exception:
                pii_count = -1

        results.append({
            "datei": str(rel),
            "ext": ext,
            "hat_clean": has_clean,
            "clean_pfad": f"{rel}.clean",
            "scannbar": can_scan,
            "pii_count": pii_count,
            "abs_pfad": str(path),
        })

    return results


def print_scan_report(results: list[dict], directory: Path, numbered: bool = False) -> None:
    print(f"\n  DSGVO PII-Datei-Scan (Presidio v2): {directory}")
    print(f"  {'=' * 68}")

    if not results:
        print("  Keine PII-relevanten Dateien gefunden.")
        return

    needs_action = [r for r in results if not r["hat_clean"]]
    already_clean = [r for r in results if r["hat_clean"]]

    if needs_action:
        print(f"\n  AKTION ERFORDERLICH ({len(needs_action)} Dateien):")
        print(f"  {'-' * 68}")
        for idx, r in enumerate(needs_action, start=1):
            pii_info = ""
            if r["scannbar"] and r["pii_count"] > 0:
                pii_info = f" [{r['pii_count']} PII-Fundstellen]"
            elif r["scannbar"] and r["pii_count"] == 0:
                pii_info = " [keine PII gefunden]"
            elif r["pii_count"] == -1:
                pii_info = " [Scan-Fehler]"
            elif not r["scannbar"]:
                pii_info = f" [Binaer/{r['ext']}]"

            if numbered:
                print(f"    [{idx:2d}] {r['datei']}{pii_info}")
            else:
                print(f"    {r['datei']}{pii_info}")

    if already_clean:
        print(f"\n  BEREITS GESCHUETZT ({len(already_clean)} Dateien):")
        print(f"  {'-' * 68}")
        for r in already_clean:
            print(f"    {r['datei']}  ->  {r['clean_pfad']}")

    total_pii = sum(r["pii_count"] for r in needs_action if r["pii_count"] > 0)
    print(f"\n  {'=' * 68}")
    print(f"  Gesamt: {len(results)} PII-Dateien, {len(needs_action)} brauchen .clean, "
          f"{len(already_clean)} bereits geschuetzt, {total_pii} PII-Fundstellen")


# ─── Deep Scan Report ────────────────────────────────

def deep_scan_file(input_path: Path) -> list[dict]:
    """Scannt eine Datei und gibt Findings mit Ersetzungswerten zurueck."""
    _reset_counters()
    ext = input_path.suffix.lower()
    if ext in (".csv",):
        return dry_run_csv(input_path, delimiter=",")
    elif ext in (".tsv",):
        return dry_run_csv(input_path, delimiter="\t")
    elif ext in (".json",):
        return dry_run_json(input_path)
    elif ext in TEXT_EXTENSIONS or ext in SOURCE_CODE_EXTENSIONS:
        return dry_run_text(input_path)
    return []


def deep_scan_report(all_files: list[dict], directory: Path) -> None:
    """Deep Scan: Zeigt alle PII-Fundstellen mit geplanten Ersetzungswerten."""
    print("\n  DEEP SCAN — Presidio + GLiNER")
    print(f"  {'=' * 68}")

    total_findings = 0
    for r in all_files:
        path = Path(r["abs_pfad"])
        ext = path.suffix.lower()
        rel = r["datei"]
        can_scan = ext in SCANNABLE_EXTENSIONS

        if not can_scan:
            print(f"\n  {rel}  [Binaer/{ext} — kein Scan moeglich]")
            continue

        _reset_counters()
        findings = deep_scan_file(path)

        if not findings:
            print(f"\n  {rel}  [keine PII gefunden]")
            continue

        status = "hat .clean" if r["hat_clean"] else "braucht .clean"
        print(f"\n  {rel}  [{len(findings)} PII, {status}]")
        print(f"  {'-' * 68}")
        for f in findings:
            ersetzt = f.get("ersetzt_durch", "")
            typ = f"{f['typ']} ({f['score']:.0%})" if "score" in f else f["typ"]
            wert = f["wert"]
            if "zeile" in f:
                line = f"    Zeile {f['zeile']:3d} | {typ:<28s} | {wert}"
            else:
                line = f"    Feld '{f['feld']}' | {typ:<28s} | {wert}"
            if ersetzt:
                line += f"  ->  {ersetzt}"
            print(line)
        total_findings += len(findings)

    print(f"\n  {'=' * 68}")
    print(f"  Gesamt: {len(all_files)} Dateien, {total_findings} PII-Fundstellen")


# ─── Interaktives Menu ────────────────────────────────

def _generate_clean_files(files: list[dict], force: bool = False) -> int:
    """Generiert .clean-Dateien. force=True ueberschreibt bestehende."""
    targets = files if force else [r for r in files if not r["hat_clean"]]
    if not targets:
        print("\n  Keine Dateien zu verarbeiten.")
        return 0

    label = "Regeneriere" if force else "Generiere"
    print(f"\n  {label} {len(targets)} .clean-Dateien...")
    print("  " + "-" * 68)
    success = 0
    for r in targets:
        inp = Path(r["abs_pfad"])
        out = Path(f"{r['abs_pfad']}.clean")
        print(f"  {r['datei']} -> {r['clean_pfad']} ... ", end="", flush=True)
        _reset_counters()
        if process_single(inp, out):
            print("OK")
            success += 1
        else:
            print("FEHLER")
    print(f"\n  {success}/{len(targets)} Dateien anonymisiert.")
    return success


def _is_source_file(r: dict) -> bool:
    """Prueft ob ein Scan-Ergebnis eine Source-Code-Datei ist."""
    return r["ext"] in SOURCE_CODE_EXTENSIONS


def _save_log(directory: Path, action: str, data: dict) -> Path:
    """Speichert Log als JSON in logs/ mit Zeitstempel."""
    logs_dir = directory / "logs"
    logs_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_file = logs_dir / f"{ts}-generate-mock-data-v2-{action}.json"
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "action": action,
        "directory": str(directory),
        **data,
    }
    log_file.write_text(json.dumps(log_entry, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"  Log: {log_file.relative_to(directory)}")
    return log_file


ACTIONS = {
    "deep-scan": "1",
    "protect-data": "2",
    "protect-source": "3",
    "regenerate-all": "4",
}


def _scan_and_categorize(directory: Path) -> dict:
    """Scannt Verzeichnis und kategorisiert Ergebnisse."""
    results_all = scan_directory(directory, include_source=True)
    results_data = [r for r in results_all if not _is_source_file(r)]
    results_source = [r for r in results_all if _is_source_file(r)]
    return {
        "all": results_all,
        "data": results_data,
        "source": results_source,
        "needs_data": [r for r in results_data if not r["hat_clean"]],
        "needs_source": [r for r in results_source if not r["hat_clean"]],
    }


def run_action(choice: str, ctx: dict, directory: Path) -> int:
    """Fuehrt eine Aktion aus. Gibt 0 bei Erfolg, 1 bei Fehler zurueck."""
    results_all = ctx["all"]
    results_data = ctx["data"]
    results_source = ctx["source"]
    needs_data = ctx["needs_data"]
    needs_source = ctx["needs_source"]

    if choice == "1":
        deep_scan_report(results_all, directory)
        scan_log = []
        for r in results_all:
            _reset_counters()
            findings = deep_scan_file(Path(r["abs_pfad"]))
            scan_log.append({
                "datei": r["datei"],
                "ext": r["ext"],
                "ist_source": _is_source_file(r),
                "hat_clean": r["hat_clean"],
                "pii_count": len(findings),
                "findings": [
                    {"typ": f["typ"], "wert": f["wert"],
                     "ersetzt_durch": f.get("ersetzt_durch", "")}
                    for f in findings
                ],
            })
        _save_log(directory, "deep-scan", {
            "dateien_gesamt": len(results_all),
            "dateien_data": len(results_data),
            "dateien_source": len(results_source),
            "ergebnisse": scan_log,
        })
        return 0

    if choice == "2":
        if not needs_data:
            print("\n  Alle Datendateien haben bereits eine .clean-Version.")
            return 0
        if results_source:
            print(f"\n  IGNORIERT (Source-Code, --action protect-source nutzen): {len(results_source)} Dateien")
            for r in results_source:
                status = "hat .clean" if r["hat_clean"] else "braucht .clean"
                print(f"    {r['datei']}  [{status}]")
        _generate_clean_files(needs_data, force=False)
        _save_log(directory, "generate-data", {
            "verarbeitet": [r["datei"] for r in needs_data],
            "ignoriert_source": [r["datei"] for r in results_source],
        })
        updated = _scan_and_categorize(directory)
        print_scan_report(updated["all"], directory)
        if not updated["needs_data"]:
            print("\n  Alle Datendateien geschuetzt.")
        return 0

    if choice == "3":
        if not needs_source:
            print("\n  Alle Source-Code-Dateien haben bereits eine .clean-Version.")
            return 0
        _generate_clean_files(needs_source, force=False)
        _save_log(directory, "generate-source", {
            "verarbeitet": [r["datei"] for r in needs_source],
        })
        updated = _scan_and_categorize(directory)
        print_scan_report(updated["all"], directory)
        if not updated["needs_source"]:
            print("\n  Alle Source-Code-Dateien geschuetzt.")
        return 0

    if choice == "4":
        _generate_clean_files(results_all, force=True)
        _save_log(directory, "regenerate-all", {
            "verarbeitet": [r["datei"] for r in results_all],
        })
        updated = _scan_and_categorize(directory)
        print_scan_report(updated["all"], directory)
        needs_all = [r for r in updated["all"] if not r["hat_clean"]]
        if not needs_all:
            print("\n  Alle .clean-Dateien erfolgreich (re)generiert.")
        return 0

    print(f"  Unbekannte Aktion: {choice}")
    return 1


def interactive_menu(directory: Path) -> int:
    print("\n  DSGVO Mock-Daten-Generator (Presidio + GLiNER)")
    print("  " + "=" * 68)
    print("  Scanne alle Dateien (inkl. Source-Code, Presidio + GLiNER aktiv)...")
    print()

    ctx = _scan_and_categorize(directory)
    print_scan_report(ctx["all"], directory)

    if not ctx["all"]:
        print("\n  Keine PII-relevanten Dateien gefunden.")
        return 0

    while True:
        print("\n  Optionen:")
        print("    [1] Deep Scan — alle PII-Fundstellen mit Ersetzungswerten anzeigen")
        print(f"    [2] Datendateien schuetzen — .clean generieren ({len(ctx['needs_data'])} Dateien)")
        print(f"    [3] + Source-Code schuetzen — .clean generieren ({len(ctx['needs_source'])} Dateien)")
        print(f"    [4] ALLE .clean-Dateien regenerieren ({len(ctx['all'])} Dateien)")
        print("    [q] Beenden")
        print()

        try:
            choice = input("  Auswahl: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if choice == "q" or choice == "":
            return 0

        if choice in ("1", "2", "3", "4"):
            run_action(choice, ctx, directory)
            # Aktualisiere Kontext nach Aktion
            ctx = _scan_and_categorize(directory)
            continue

        print(f"  Unbekannte Eingabe: {choice}")

    return 0


# ─── Main ─────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="DSGVO Mock-Daten-Generator (Presidio + GLiNER)"
    )
    parser.add_argument("input", nargs="?", default=None,
                        help="Eingabedatei (oder leer fuer interaktives Menu)")
    parser.add_argument("--output", "-o", help="Ausgabedatei (Standard: <input>.clean)")
    parser.add_argument("--dry", action="store_true",
                        help="Nur PII-Fundstellen anzeigen, nichts schreiben")
    parser.add_argument("--dir", "-d", default=".",
                        help="Verzeichnis fuer Scan (Standard: aktuelles Verzeichnis)")
    parser.add_argument("--all", action="store_true",
                        help="Alle Dateien scannen inkl. Source-Code")
    parser.add_argument("--action", "-a",
                        choices=list(ACTIONS.keys()),
                        help="Aktion direkt ausfuehren ohne interaktives Menu: "
                             "deep-scan, protect-data, protect-source, regenerate-all")
    args = parser.parse_args()

    # --action: Direkte Ausfuehrung ohne Menu
    if args.action:
        directory = Path(args.dir).resolve()
        if not directory.is_dir():
            print(f"Fehler: Verzeichnis nicht gefunden: {directory}", file=sys.stderr)
            return 1
        print(f"\n  DSGVO Mock-Daten-Generator — Aktion: {args.action}")
        print("  " + "=" * 68)
        print("  Scanne Verzeichnis...")
        print()
        ctx = _scan_and_categorize(directory)
        print_scan_report(ctx["all"], directory)
        if not ctx["all"]:
            print("\n  Keine PII-relevanten Dateien gefunden.")
            return 0
        return run_action(ACTIONS[args.action], ctx, directory)

    # Kein Input und kein --dry: Interaktives Menu
    if args.input is None and not args.dry:
        directory = Path(args.dir).resolve()
        if not directory.is_dir():
            print(f"Fehler: Verzeichnis nicht gefunden: {directory}", file=sys.stderr)
            return 1
        return interactive_menu(directory)

    # --dry ohne Input: Verzeichnis scannen
    if args.input is None:
        directory = Path(args.dir).resolve()
        if not directory.is_dir():
            print(f"Fehler: Verzeichnis nicht gefunden: {directory}", file=sys.stderr)
            return 1
        results = scan_directory(directory, include_source=args.all)
        print_scan_report(results, directory, numbered=True)
        return 0

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Fehler: Datei nicht gefunden: {input_path}", file=sys.stderr)
        return 1

    if args.dry:
        return dry_run_single(input_path)

    output_path = Path(args.output) if args.output else Path(f"{input_path}.clean")
    _reset_counters()
    if process_single(input_path, output_path):
        print(f"Clean-Datei erstellt: {output_path}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
