"""PDF text extraction service."""

import pdfplumber
from io import BytesIO
from app.config import get_settings

settings = get_settings()


class PDFExtractionError(Exception):
    """Raised when PDF extraction fails."""
    pass


class EmptyPDFError(Exception):
    """Raised when extracted text is too short."""
    pass


def extract_text_from_pdf(file_content: bytes) -> str:
    """
    Extract text from a PDF file.
    
    Args:
        file_content: Raw bytes of the PDF file
        
    Returns:
        Extracted text as a string
        
    Raises:
        PDFExtractionError: If the PDF cannot be read
        EmptyPDFError: If extracted text is too short (likely image-based PDF)
    """
    try:
        with pdfplumber.open(BytesIO(file_content)) as pdf:
            text_parts = []
            
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)
            
            full_text = "\n\n".join(text_parts).strip()
            
    except Exception as e:
        raise PDFExtractionError(f"Failed to read PDF: {str(e)}")
    
    # Check minimum length
    if len(full_text) < settings.min_resume_chars:
        raise EmptyPDFError(
            f"Extracted text is too short ({len(full_text)} chars). "
            "This PDF may be image-based or empty. Please upload a text-based PDF."
        )
    
    return full_text
