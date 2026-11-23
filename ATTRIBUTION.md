# Происхождение и благодарности

XBOX-Inspector 0.2.0 — независимая реализация на Rust. Использованы:

- **SimuXBOX 0.1.0** (MIT) — базовые наблюдения форматов RPF9/RDS5/ETPF/Bink,
  референсные парсеры (`rds5.py`, `rpf9_video.py`, `rpf9.py`, `pe_intake.py`)
  и проверочные индексы (`Claims.json`, `VIDEO_FRESH_SCAN.json`,
  `Unified_Source_Verification.jsonl`), включённые в `indexes/` с привязкой
  к снимку. Код переписан на Rust; исходники Python сохранены как база знаний.
- **SixNG** (holdmysocks) — наблюдение заголовка RPF9 (word_04 как граница
  кандидата каталога).
- **PercyStar** (rpatty-dev) — наблюдения буферов вершин/мешлетов RAGE 9.
- **IETF RFC 1950** — формат ZLIB; независимая проверка через miniz_oxide
  (flate2 rust_backend).
- **Microsoft** — формат PE, FSCTL_QUERY_ALLOCATED_RANGES, спецификация DXIL.
- **Autodesk Scaleform** — документация обмена ActionScript ↔ приложение.
- **XCL / ScarlettX / Xbox2Windows** — упомянуты как внешние слои
  совместимости; их код не включён и не выполнялся.

Игровые файлы исходной сборки не включены в поставку и не модифицировались.