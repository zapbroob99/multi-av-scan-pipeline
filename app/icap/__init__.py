"""ICAP gateway for MASP.

A self-contained asyncio ICAP (RFC 3507) server that fronts the existing scan
pipeline. It is a second entry point alongside the REST API, not a replacement:
a storage system sends a file over ICAP, MASP scans it with
the same engines and decision logic, and returns allow (204) or block (200).
"""
