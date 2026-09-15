**Unreleased**

* Encoded caller-supplied identifiers before passing them to Incydr SDK path endpoints.
* Rejected empty and dot-segment identifiers before Incydr SDK path construction.
* Bounded on-poll session and event accumulation and removed the unsupported event continuation call.
* Prevented the poll checkpoint from advancing past failed session ingests and added a fallback container name.
* Prevented the poll checkpoint from advancing when artifact persistence or existing-container reconciliation fails.
* Applied strict path-segment validation to caller-supplied and API-returned polling session identifiers.
* Removed Unicode format-control characters from Code42 session and file-event fields exposed through SOAR containers and artifacts.
