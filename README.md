# Resume Tailor

Core logic for a privacy-first resume tailoring service.

## Architecture

- **Zero-storage**: Resumes are processed in RAM only. No files are written to disk.
- **IP hashing**: User IPs are SHA256-hashed before any storage. Plaintext IPs are never persisted.
- **No accounts**: Users are identified by anonymous session cookies. No email or signup required.

## What's in this repo

This repository contains a subset of the production codebase to demonstrate the privacy architecture:

| File | Purpose |
|------|---------|
| `app/services/credit_service.py` | IP hashing logic, credit management |
| `app/services/pdf_extract.py` | In-memory PDF text extraction |
| `app/routes/api.py` | Main API endpoint (no disk writes) |

## Tech Stack

- Python 3.11+
- FastAPI
- SQLite (credits/sessions only, no documents)
- pdfplumber

## Live Demo

[deadsimpletools.com/resume-tailor](https://deadsimpletools.com/resume-tailor)

## License

MIT
