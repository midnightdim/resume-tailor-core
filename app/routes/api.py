"""Main API routes for resume tailoring."""

import base64
from datetime import datetime
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.database import get_db
from app.models.schemas import TailorRequest, TailorResponse, ErrorResponse, ErrorCode, ErrorReport
from app.services.pdf_extract import extract_text_from_pdf, PDFExtractionError, EmptyPDFError
from app.services.ai_service import tailor_resume, AIServiceError, FreeApiExhaustedError
from app.services.pdf_generate import generate_pdf, render_resume_html, resume_to_text, generate_cover_letter_pdf, render_cover_letter_html
from app.services.credit_service import get_user_balance, deduct_credit, log_usage, peek_credit_type
from app.dependencies import get_session_user, get_ip_hash

settings = get_settings()
router = APIRouter()


@router.post("/tailor", response_model=TailorResponse | ErrorResponse)
async def tailor_resume_endpoint(
    request: Request,
    body: TailorRequest,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_session_user),
    ip_hash: str = Depends(get_ip_hash)
):
    """
    Tailor a resume to match a job description.
    Zero-storage pipeline: RAM only.
    Uses tiered model selection based on credit type.
    """
    from app.dependencies import get_client_ip
    from app.config import get_settings
    _settings = get_settings()
    raw_ip = get_client_ip(request) if _settings.log_real_ips else None
    
    # 1. Check Balance (with IP rate limiting for new users)
    # Determine cost: 1 credit for resume, +1 for cover letter
    required_credits = 2 if body.include_cover_letter else 1
    
    balance = await get_user_balance(db, user_id, ip_hash, raw_ip)
    
    # Pre-flight check: Ensure user has enough total credits
    if balance["total"] < required_credits:
        await log_usage(db, user_id, "generate_cv", "failed", {"reason": "insufficient_credits", "required": required_credits})
        return JSONResponse(
            status_code=402,
            content={
                "success": False,
                "error": f"Insufficient credits. You need {required_credits} credits for this operation.",
                "error_code": ErrorCode.RATE_LIMITED
            }
        )

    # 2. Determine credit tier BEFORE processing (for model selection)
    credit_type = await peek_credit_type(db, user_id)
    is_paid_tier = (credit_type == "paid")

    try:
        # Decode PDF
        try:
            if "," in body.resume_base64:
                _, encoded = body.resume_base64.split(",", 1)
            else:
                encoded = body.resume_base64
            content = base64.b64decode(encoded)
            
            if len(content) > settings.max_upload_mb * 1024 * 1024:
                raise ValueError("File too large")
                
        except Exception:
            return ErrorResponse(
                error="Invalid PDF.",
                error_code=ErrorCode.INVALID_PDF
            )

        # Extract Text
        try:
            resume_text = extract_text_from_pdf(content)
        except (EmptyPDFError, PDFExtractionError) as e:
            return ErrorResponse(error=str(e), error_code=ErrorCode.INVALID_PDF)

        # Validate input lengths
        job_desc = body.job_description.strip()
        context = (body.additional_context or "").strip()
        
        if len(resume_text) < settings.min_resume_chars:
            return ErrorResponse(error="Resume is too short.", error_code=ErrorCode.INVALID_PDF)
        if len(resume_text) > settings.max_resume_chars:
            return ErrorResponse(error=f"Resume too long ({len(resume_text)} chars). Max: {settings.max_resume_chars}.", error_code=ErrorCode.INVALID_PDF)
        if len(job_desc) < settings.min_job_desc_chars:
            return ErrorResponse(error="Job description is too short.", error_code=ErrorCode.INVALID_INPUT)
        if len(job_desc) > settings.max_job_desc_chars:
            return ErrorResponse(error=f"Job description too long ({len(job_desc)} chars). Max: {settings.max_job_desc_chars}.", error_code=ErrorCode.INVALID_INPUT)
        if len(context) > settings.max_context_chars:
            return ErrorResponse(error=f"Additional context too long. Max: {settings.max_context_chars} chars.", error_code=ErrorCode.INVALID_INPUT)

        # Process with AI (tiered model selection)
        try:
            structured_resume, ai_warning, model_info = await tailor_resume(
                resume_text=resume_text,
                job_description=job_desc,
                additional_context=context if context else None,
                is_paid_tier=is_paid_tier,
                include_cover_letter=body.include_cover_letter,
                db=db,
                user_id=user_id
            )
        except FreeApiExhaustedError as e:
            # Free API quota exhausted - ai_service already logged with provider/model details
            return JSONResponse(
                status_code=503,
                content={
                    "success": False,
                    "error": str(e),
                    "error_code": ErrorCode.FREE_API_EXHAUSTED
                }
            )
        except AIServiceError as e:
            # ai_service already logged failure with provider/model details
            return ErrorResponse(error=f"AI Error: {str(e)}", error_code=ErrorCode.AI_ERROR)
        
        # Generate PDF (In-Memory)
        try:
            pdf_buffer = generate_pdf(structured_resume, is_paid_tier=is_paid_tier)
            pdf_b64 = base64.b64encode(pdf_buffer.getvalue()).decode('utf-8')
            
            # Generate Cover Letter PDF if present
            cover_letter_pdf_b64 = None
            if structured_resume.cover_letter:
                cl_buffer = generate_cover_letter_pdf(structured_resume.cover_letter, structured_resume, is_paid_tier=is_paid_tier)
                cover_letter_pdf_b64 = base64.b64encode(cl_buffer.getvalue()).decode('utf-8')
                
        except Exception as e:
            await log_usage(db, user_id, "generate_cv", "failed", {"error": "pdf_gen_failed"})
            return ErrorResponse(error="PDF generation failed.", error_code=ErrorCode.AI_ERROR)


        # 4. Deduct Credit (On Success) - IP rate limit is recorded here for free credits
        try:
            deducted_type = await deduct_credit(db, user_id, ip_hash, amount=required_credits)
        except ValueError:
            # Race condition: ran out of credit during processing
            return JSONResponse(
                status_code=402,
                content={
                    "success": False,
                    "error": "Insufficient credits to complete request.",
                    "error_code": ErrorCode.RATE_LIMITED
                }
            )

        # Success - Log with model info for debugging
        log_metadata = {
            "credit_type": deducted_type,
            "provider": model_info.provider if model_info else "unknown",
            "model": model_info.model if model_info else "unknown",
            "key_index": model_info.key_index if model_info else 0
        }
        await log_usage(db, user_id, "generate_cv", "success", log_metadata)
        
        resume_html = render_resume_html(structured_resume)
        resume_text_output = resume_to_text(structured_resume)
        
        # Prepare cover letter outputs
        cl_text = structured_resume.cover_letter
        cl_html = render_cover_letter_html(cl_text) if cl_text else None
        
        # Get updated credits
        updated_credits = await get_user_balance(db, user_id)
        
        return TailorResponse(
            success=True,
            name=structured_resume.name,
            title=structured_resume.title,
            resume_text=resume_text_output,
            resume_html=resume_html,
            pdf_base64=pdf_b64,
            cover_letter_text=cl_text,
            cover_letter_html=cl_html,
            cover_letter_pdf_base64=cover_letter_pdf_b64,
            warning=ai_warning,
            remaining_free_credits=updated_credits["free"],
            remaining_paid_credits=updated_credits["paid"],
            show_branding=not is_paid_tier  # Free tier gets branded filenames
        )

    except Exception as e:
        await log_usage(db, user_id, "error", "failed", {"exception": str(e)})
        return JSONResponse(status_code=500, content={"error": f"Internal Error: {str(e)}"})


@router.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "mode": "zero-storage"}


@router.get("/balance")
async def get_balance(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(get_session_user),
    ip_hash: str = Depends(get_ip_hash)
):
    """Get current credit balance with optional notification."""
    from app.dependencies import get_client_ip
    from app.config import get_settings
    _settings = get_settings()
    raw_ip = get_client_ip(request) if _settings.log_real_ips else None
    
    balance = await get_user_balance(db, user_id, ip_hash, raw_ip)
    
    # Add notification for special states
    # Paid users should never see these - they paid to bypass limits
    notification = None
    
    if balance.get("paid", 0) == 0:
        if balance.get("ip_limited"):
            # IP abuse prevention - multiple sessions from same network
            notification = {
                "type": "ip_limited",
                "title": "Daily Limit Reached",
                "message": "Multiple sessions detected from your network today. Free credits will refresh tomorrow, or you can purchase premium credits for instant access."
            }
        elif balance.get("credits_exhausted"):
            # Normal usage - user legitimately used all their credits
            notification = {
                "type": "credits_exhausted",
                "title": "Credits Used Up",
                "message": "You've used all your free credits for today. Come back tomorrow for more, or get premium credits for instant access."
            }
    
    return {
        **balance,
        "notification": notification
    }


@router.post("/report-error")
async def report_error(body: ErrorReport):
    """Log a client-side system error for developer awareness."""
    from app.services.logger_service import log_event, LogLevel, LogSource
    
    metadata = {
        "url": body.url,
        "stack_trace": body.stack_trace,
        "browser": "Captured via stacks" # Metadata already contains stack trace
    }
    
    await log_event(
        level=LogLevel.ERROR,
        source=LogSource.CLIENT,
        message=f"UI Error: {body.error_message}",
        metadata=metadata
    )
    
    # Still print for console visibility
    print(f"!!! SYSTEM ERROR REPORTED: {body.error_message}")
    
    return {"success": True}
