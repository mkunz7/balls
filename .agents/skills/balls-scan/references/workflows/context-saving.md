# Context saving

Scans can exceed one conversation context. Keep durable state in the scan directory, not in a long chat transcript.

At each stage boundary, save component maps, completed coverage units, candidate and verification records, and unresolved questions to their scan artifacts. Hunters and verifiers should return concise evidence summaries with file and line references. The coordinator can then resume after Antigravity compacts context (e.g. `/compact`) or in a new session by following `scan-resumption.md`.

Do not rely on editor hooks or hidden session memory. If compaction is imminent, update `progress.md`, verify DB writes, and list the next concrete actions before continuing.
