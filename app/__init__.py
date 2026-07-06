"""Multiforum security-scan microservice.

A small FastAPI service that inspects file attachments uploaded to Multiforum
forums. It is invoked out-of-process by the ``security-attachment-scan`` plugin
(a thin TypeScript shim running inside the Node backend) whenever a
``downloadableFile.*`` event fires.

The service performs two independent checks and merges them into a single
verdict:

* a VirusTotal reputation lookup (by file hash), and
* static analysis of ZIP archives (disallowed file types, decompression-ratio
  "zip bomb" guard, and README/LICENSE presence for the downloads workflow).
"""

__version__ = "0.1.0"
