# Внешние проверки и инструменты

Ядро и обход папки остаются в Rust. Перекодирование известных открытых потоков, статическая проверка PE и формирование отчётов используют один общий конвейер для CLI и GUI. Внешние программы запускаются отдельно только на явно выбранном входе. В релиз вошёл собственный код и разрешённые шрифты. Исходный код внешних проектов, их игровые образцы и библиотеки в ZIP не включены.

| Проект | Просмотренный коммит | Что проверено для этого проекта |
| --- | --- | --- |
| [XCL](https://github.com/ivall/xcl/tree/9add7213c6b38752c0982eadd3bae3d90522473e) | `9add7213c6b38752c0982eadd3bae3d90522473e` | Просмотрены GPLv2 и нативный загрузчик. При отсутствии указанного PE загрузчик возвращает ошибку. Это сравнивалось с нашим статическим preflight. |
| [Leonida](https://github.com/ItsNotRexed/Leonida/tree/8575d36edc479218972497a7bded8651a42856c0) | `8575d36edc479218972497a7bded8651a42856c0` | Просмотрены README и файл GPLv3. Сравнивались заявленные требования к локально подготовленному входу. |
| [Xbox2Windows](https://github.com/R0Y00/Xbox2Windows/tree/2629d412fd2a9147704f0447091543ce29b6e706) | `2629d412fd2a9147704f0447091543ce29b6e706` | Просмотрены README и MIT. Подход с собственными тестовыми входами применён в нашей верификации диапазонов и PE. |
| [ScarlettX](https://github.com/Freminet/ScarlettX/tree/01c642cf62a6d9978f535e2c438c488ebcb4cd39) | `01c642cf62a6d9978f535e2c438c488ebcb4cd39` | Просмотрен README. Запрос файла LICENSE по этому коммиту вернул 404. Разрешение на перенос кода не установлено. |

### Ghidra 12.2

Адаптер экспортирует статические метаданные одного явно выбранного PE в JSON. Для проверки использовался `tools/fixtures/owned_pe.rs` из исходного пакета. Архитектура, формат и SHA‑256 сверены. Никакой гостевой код при этом не выполнялся. Адаптер пишет ограниченный результат вне выбранной папки входа.

~~~powershell
New-Item -ItemType Directory -Force .\fixture, .\reports
rustc tools\fixtures\owned_pe.rs -o .\fixture\owned.exe
python tools\ghidra_metadata.py --ghidra-home 'C:\путь\к\ghidra' --input-root .\fixture --pe .\fixture\owned.exe --output .\reports\pe.json
~~~

### MCP FileSystem для отчётов

В канале stdio инспектор предоставляет два инструмента `list_reports` и `read_report`. Они ограничены выбранной папкой отчётов. Поддерживаются JSON и Markdown, чтение идёт страницами с ограничением размера. Сервер не имеет инструментов записи и не открывает сетевой порт. Для автоконфигурации укажи в MCP-клиенте путь к выпущенному `XBOX-Inspector.exe` как команду и аргументы `mcp-reports`, затем абсолютный путь к отдельной папке готовых отчётов.

~~~powershell
.\bin\XBOX-Inspector.exe mcp-reports 'C:\путь\к\отчётам'
~~~

[Официальная документация Ghidra](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md) · [Транспорт MCP stdio](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
