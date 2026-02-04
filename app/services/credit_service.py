"""Service for managing credits, usage logging, and IP rate limiting."""
import hashlib
import uuid
import logging
from datetime import date, datetime
from typing import Optional, Tuple
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import User, UsageLog, IpRateLimit, BannedIp, PendingOrder
from app.config import get_settings

settings = get_settings()
logger = logging.getLogger("credits")


def generate_user_id() -> str:
    """Generate a secure, unique user ID."""
    return uuid.uuid4().hex


def hash_ip(ip: str) -> str:
    """Hash an IP address for privacy-preserving rate limiting."""
    return hashlib.sha256(f"{ip}-{settings.secret_key}".encode()).hexdigest()


async def is_ip_banned(db: AsyncSession, ip_hash: str) -> bool:
    """Check if an IP address is banned."""
    result = await db.execute(
        select(BannedIp).where(BannedIp.ip_hash == ip_hash)
    )
    return result.scalar_one_or_none() is not None


async def ban_ip(db: AsyncSession, ip_hash: str, reason: str = None) -> None:
    """Ban an IP address."""
    banned = BannedIp(
        ip_hash=ip_hash,
        reason=reason,
        banned_at=datetime.utcnow()
    )
    db.add(banned)
    await db.commit()


async def unban_ip(db: AsyncSession, ip_hash: str) -> bool:
    """Unban an IP address. Returns True if IP was found and unbanned."""
    from sqlalchemy import delete
    result = await db.execute(
        delete(BannedIp).where(BannedIp.ip_hash == ip_hash)
    )
    await db.commit()
    return result.rowcount > 0


async def check_ip_rate_limit(db: AsyncSession, ip_hash: str) -> bool:
    """
    Check if IP has exceeded free credit issuance limit.
    Returns True if within limit, False if exceeded.
    """
    today = date.today()
    ip_short = ip_hash[:8]
    
    result = await db.execute(
        select(IpRateLimit).where(IpRateLimit.ip_hash == ip_hash)
    )
    ip_limit = result.scalar_one_or_none()
    
    if not ip_limit:
        logger.info(f"[IP] {ip_short}... NEW IP, allowing credits")
        return True
    
    if ip_limit.last_reset_date < today:
        logger.info(f"[IP] {ip_short}... new day, resetting counter")
        return True
    
    issued = ip_limit.free_credits_issued_today
    limit = settings.ip_free_credit_limit
    can_issue = issued < limit
    logger.info(f"[IP] {ip_short}... {issued}/{limit} today, can_issue={can_issue}")
    return can_issue


async def record_ip_credit_issuance(db: AsyncSession, ip_hash: str, credits_used: int = 1) -> None:
    """Record that free credits were used from this IP."""
    today = date.today()
    
    result = await db.execute(
        select(IpRateLimit).where(IpRateLimit.ip_hash == ip_hash)
    )
    ip_limit = result.scalar_one_or_none()
    
    if not ip_limit:
        # Create new record with actual credits used
        ip_limit = IpRateLimit(
            ip_hash=ip_hash,
            free_credits_issued_today=credits_used,
            last_reset_date=today
        )
        db.add(ip_limit)
    elif ip_limit.last_reset_date < today:
        # New day, reset counter with current usage
        ip_limit.free_credits_issued_today = credits_used
        ip_limit.last_reset_date = today
    else:
        # Same day, add actual credits used
        ip_limit.free_credits_issued_today += credits_used
    
    await db.commit()


async def get_user_balance(
    db: AsyncSession, 
    user_id: str, 
    ip_hash: Optional[str] = None,
    raw_ip: Optional[str] = None
) -> dict:
    """
    Get current credit balance with Lazy Reset.
    If reset is needed, updates DB and commits immediately.
    
    For new users: checks IP rate limit before issuing free credits.
    Paid users bypass IP limits.
    
    Args:
        raw_ip: Real IP address (only stored when LOG_REAL_IPS=true)
    """
    today = date.today()
    
    # 1. Fetch or Create
    result = await db.execute(select(User).where(User.user_id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        # New user - check IP rate limit
        can_issue = True
        if ip_hash:
            can_issue = await check_ip_rate_limit(db, ip_hash)
        
        initial_credits = settings.free_credits_per_session if can_issue else 0
        
        user = User(
            user_id=user_id,
            ip_hash=ip_hash,  # Always store hashed IP
            raw_ip=raw_ip,  # Only populated when LOG_REAL_IPS=true
            free_credits=initial_credits,
            paid_credits=0,
            last_reset_date=today,
            created_at=datetime.utcnow()
        )
        db.add(user)
        await db.commit()
        
        # NOTE: IP rate limit is now recorded on credit USAGE, not issuance
        # This prevents bots from consuming the IP quota
        
        logger.info(f"[USER] NEW user={user_id[:8]}... credits={initial_credits} ip_limited={not can_issue}")
        
        return {
            "free": initial_credits, 
            "paid": 0, 
            "total": initial_credits,
            "ip_limited": not can_issue,  # True only if blocked by IP abuse prevention
            "credits_exhausted": False  # New user hasn't used any credits yet
        }
    
    # Update raw_ip if provided (for existing users when debug is enabled)
    if raw_ip and user.raw_ip != raw_ip:
        user.raw_ip = raw_ip
        await db.commit()
    
    # 2. Lazy Reset Check (only for users without paid credits)
    db_date = user.last_reset_date
    if isinstance(db_date, str):
        try:
            db_date = datetime.strptime(db_date, "%Y-%m-%d").date()
        except Exception:
            db_date = today
    
    if db_date < today:
        # Check if user has paid credits (bypass IP limit)
        if user.paid_credits > 0:
            user.free_credits = settings.free_credits_per_session
            user.last_reset_date = today
            await db.commit()
        elif ip_hash:
            # Check IP rate limit for free credit reset
            can_issue = await check_ip_rate_limit(db, ip_hash)
            if can_issue:
                user.free_credits = settings.free_credits_per_session
                user.last_reset_date = today
                await db.commit()
                # NOTE: IP rate limit is now recorded on credit USAGE, not reset
            else:
                user.free_credits = 0
                user.last_reset_date = today
                await db.commit()
        else:
            # No IP hash provided, allow reset
            user.free_credits = settings.free_credits_per_session
            user.last_reset_date = today
            await db.commit()
    
    # Determine notification state:
    # - ip_limited: User was blocked from getting initial credits (no usage history, 0 credits)
    # - credits_exhausted: User legitimately used all their credits (has usage history)
    is_ip_limited = False
    credits_exhausted = False
    
    if user.free_credits == 0 and user.paid_credits == 0:
        # Check if user has any usage history
        from app.db.models import UsageLog
        usage_result = await db.execute(
            select(UsageLog).where(UsageLog.user_id == user_id).limit(1)
        )
        has_usage = usage_result.scalar_one_or_none() is not None
        
        if has_usage:
            # User used credits legitimately
            credits_exhausted = True
        else:
            # User has no history and 0 credits = blocked at creation
            is_ip_limited = True
    
    return {
        "free": int(user.free_credits),
        "paid": int(user.paid_credits),
        "total": int(user.free_credits) + int(user.paid_credits),
        "user_id": user_id,
        "ip_limited": is_ip_limited,
        "credits_exhausted": credits_exhausted
    }


async def deduct_credit(db: AsyncSession, user_id: str, ip_hash: Optional[str] = None, amount: int = 1) -> str:
    """
    Deduct credits atomically. Priorities: Free -> Paid.
    Supports mixed buckets (e.g., 1 free + 1 paid for 2-credit operations).
    
    Returns 'free', 'paid', or 'mixed' to indicate which type(s) were deducted.
    
    If FREE credits are used and ip_hash is provided, records the usage
    against the IP rate limit (prevents abuse while ignoring bots).
    
    Raises ValueError if insufficient total credits.
    """
    # Ensure user exists and reset is applied
    balance = await get_user_balance(db, user_id)
    
    free_available = balance["free"]
    paid_available = balance["paid"]
    total_available = free_available + paid_available
    
    if total_available < amount:
        raise ValueError("Insufficient credits")
    
    # Calculate how to split the deduction
    free_to_deduct = min(free_available, amount)
    paid_to_deduct = amount - free_to_deduct
    
    # Fetch the user for update
    result = await db.execute(select(User).where(User.user_id == user_id))
    user = result.scalar_one()
    
    # Apply deductions
    if free_to_deduct > 0:
        user.free_credits -= free_to_deduct
    if paid_to_deduct > 0:
        user.paid_credits -= paid_to_deduct
    
    await db.commit()
    
    # Record IP usage if any FREE credits were consumed
    if free_to_deduct > 0 and ip_hash:
        await record_ip_credit_issuance(db, ip_hash, free_to_deduct)
    
    # Return credit type used (for logging and model selection)
    if free_to_deduct > 0 and paid_to_deduct > 0:
        return "mixed"
    elif paid_to_deduct > 0:
        return "paid"
    else:
        return "free"


async def peek_credit_type(db: AsyncSession, user_id: str) -> str:
    """
    Check which credit type will be used next (without deducting).
    Returns 'free', 'paid', or 'none'.
    """
    result = await db.execute(select(User).where(User.user_id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        return "none"
    if user.free_credits > 0:
        return "free"
    if user.paid_credits > 0:
        return "paid"
    return "none"


async def add_paid_credits(db: AsyncSession, user_id: str, amount: int) -> None:
    """Add paid credits to a user."""
    # Ensure user exists
    await get_user_balance(db, user_id)
    
    stmt = update(User).where(User.user_id == user_id).values(
        paid_credits=User.paid_credits + amount
    )
    await db.execute(stmt)
    await db.commit()
    
    # Verify and log
    result = await db.execute(select(User).where(User.user_id == user_id))
    updated_user = result.scalar_one_or_none()
    if updated_user:
        logger.info(f"[CREDIT] Added {amount} paid credits to {user_id[:8]}... New Paid Balance: {updated_user.paid_credits}")
    else:
        logger.error(f"[CREDIT] FAILED to verify update for {user_id}")


async def log_usage(
    db: AsyncSession, 
    user_id: str, 
    action: str, 
    status: str, 
    metadata: Optional[dict] = None
):
    """Log an action for debugging/stats (non-blocking)."""
    log_entry = UsageLog(
        user_id=user_id,
        action=action,
        status=status,
        timestamp=datetime.utcnow(),
        metadata_json=metadata
    )
    db.add(log_entry)
    await db.commit()


# === Cleanup Functions ===

async def cleanup_inactive_users(db: AsyncSession) -> int:
    """
    Delete inactive free users to prevent database bloat.
    
    Criteria:
    - paid_credits = 0
    - free_credits = 0
    - last_reset_date < today - inactive_user_cleanup_days
    
    Returns: Number of users deleted
    """
    from datetime import timedelta
    from sqlalchemy import delete
    
    cutoff_date = date.today() - timedelta(days=settings.inactive_user_cleanup_days)
    
    result = await db.execute(
        delete(User).where(
            User.paid_credits == 0,
            User.free_credits == 0,
            User.last_reset_date < cutoff_date
        )
    )
    
    await db.commit()
    return result.rowcount


async def cleanup_stale_ip_records(db: AsyncSession) -> int:
    """
    Delete stale IP rate limit records (they reset daily anyway).
    
    Criteria:
    - last_reset_date < today - ip_rate_limit_cleanup_days
    
    Returns: Number of records deleted
    """
    from datetime import timedelta
    from sqlalchemy import delete
    
    cutoff_date = date.today() - timedelta(days=settings.ip_rate_limit_cleanup_days)
    
    result = await db.execute(
        delete(IpRateLimit).where(
            IpRateLimit.last_reset_date < cutoff_date
        )
    )
    
    await db.commit()
    return result.rowcount


async def cleanup_unused_sessions(db: AsyncSession, hours_threshold: int = 2) -> int:
    """
    Delete users who never used the service (no usage logs).
    
    These are likely bots or window-shoppers who visited but never
    actually tailored a resume. Safe to delete as they have no history.
    
    Criteria:
    - created_at < now - hours_threshold
    - No entries in usage_logs table for this user_id
    - paid_credits = 0 (NEVER delete paying customers!)
    
    Returns: Number of users deleted
    """
    from datetime import timedelta
    from sqlalchemy import delete, exists, select
    
    cutoff_time = datetime.utcnow() - timedelta(hours=hours_threshold)
    
    # Find users with no usage logs who are old enough
    # Subquery: users who have at least one usage log
    users_with_logs = select(UsageLog.user_id).distinct()
    
    result = await db.execute(
        delete(User).where(
            User.created_at < cutoff_time,
            User.paid_credits == 0,  # NEVER delete paying customers
            ~User.user_id.in_(users_with_logs)
        )
    )
    
    await db.commit()
    return result.rowcount


async def cleanup_usage_logs(db: AsyncSession, days: int = None) -> int:
    """
    Delete old usage logs to prevent database bloat.
    
    Criteria:
    - timestamp < today - days (default: usage_log_cleanup_days)
    
    Returns: Number of records deleted
    """
    from datetime import timedelta
    from sqlalchemy import delete
    
    cleanup_days = days if days is not None else settings.usage_log_cleanup_days
    cutoff_date = datetime.utcnow() - timedelta(days=cleanup_days)
    
    # If days=0, we want to clear EVERYTHING, so cutoff is "now"
    if cleanup_days == 0:
        cutoff_date = datetime.utcnow()
    
    result = await db.execute(
        delete(UsageLog).where(
            UsageLog.timestamp < cutoff_date
        )
    )
    
    await db.commit()
    return result.rowcount


async def cleanup_pending_orders(db: AsyncSession, days_threshold: int = 7) -> int:
    """
    Delete abandoned pending orders to prevent database bloat.
    
    Criteria:
    - created_at < now - days_threshold
    - status = 'pending'
    
    Returns: Number of orders deleted
    """
    from datetime import timedelta
    from sqlalchemy import delete
    
    cutoff_time = datetime.utcnow() - timedelta(days=days_threshold)
    
    result = await db.execute(
        delete(PendingOrder).where(
            PendingOrder.created_at < cutoff_time,
            PendingOrder.status == "pending"
        )
    )
    
    await db.commit()
    return result.rowcount


async def run_all_cleanup(db: AsyncSession) -> dict:
    """Run all cleanup tasks and return summary."""
    users_deleted = await cleanup_inactive_users(db)
    ips_deleted = await cleanup_stale_ip_records(db)
    unused_deleted = await cleanup_unused_sessions(db)
    usage_logs_deleted = await cleanup_usage_logs(db)
    pending_orders_deleted = await cleanup_pending_orders(db)
    
    return {
        "inactive_users_deleted": users_deleted,
        "stale_ip_records_deleted": ips_deleted,
        "unused_sessions_deleted": unused_deleted,
        "usage_logs_deleted": usage_logs_deleted,
        "pending_orders_deleted": pending_orders_deleted
    }
