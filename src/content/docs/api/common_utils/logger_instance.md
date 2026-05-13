---
title: mscp.common_utils.logger_instance
description: "Singleton `loguru` logger used throughout mSCP."
---

> Source: [`src/mscp/common_utils/logger_instance.py`](https://github.com/usnistgov/macos_security/blob/dev_2.0/src/mscp/common_utils/logger_instance.py)

Singleton `loguru` logger used throughout mSCP.

Imports the global `loguru` logger, removes its default sink (so log
output isn't emitted until `set_logger` is called), and re-exports it
as `logger`.
