# Resume Tailor - Privacy-First Resume Rewriter

## What It Does
Rewrites your resume to match job descriptions using AI. Zero-storage architecture.

## Privacy Architecture
- **No Database Storage**: Resumes processed in-memory only
- **IP Privacy**: User IPs are SHA256-hashed, never stored in plaintext
- **Immediate Wipe**: All uploads deleted after PDF generation
- **No Email Collection**: Works without signup

## Tech Stack
- FastAPI (async)
- SQLite (user credits only, no documents)
- Gemini 3 Flash + OpenRouter fallback
- Single VPS deployment

## Code Highlights
See `/app/services/credit_service.py` for IP hashing implementation.

## Live Demo
[deadsimpletools.com/resume-tailor](https://deadsimpletools.com/resume-tailor)

## License
MIT
