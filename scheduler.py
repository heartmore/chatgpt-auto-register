"""Daily invite key generation scheduler"""

from apscheduler.schedulers.background import BackgroundScheduler
import db, config

_scheduler = None


def start_scheduler():
    global _scheduler
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(
        _gen_daily, 'cron', hour=0, minute=0,
        id='daily_invite_gen'
    )
    _scheduler.start()
    print("[Scheduler] Daily invite generation started (00:00)")


def _gen_daily():
    try:
        keys = db.gen_invite_keys(count=config.DAILY_INVITE_COUNT, quota=config.DAILY_INVITE_QUOTA)
        print(f"[Scheduler] Generated {len(keys)} invite keys: {keys}")
    except Exception as e:
        print(f"[Scheduler] Failed: {e}")
