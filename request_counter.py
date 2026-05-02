"""
Request counter for Google Apps Script quota monitoring.
With custom reset time at 10:30 AM Iran time (UTC+3:30).
"""

import json
import os
from datetime import datetime, timedelta, timezone

# تنظیمات
RESET_HOUR = 10
RESET_MINUTE = 30
IRAN_UTC_OFFSET = 3.5  # ایران UTC+3:30


class RequestCounter:
    def __init__(self, filename="usage_stats.json"):
        self.filename = filename
        self.load_stats()
    
    def _get_tehran_time(self):
        """Get current time in Tehran (UTC+3:30)"""
        utc_now = datetime.now(timezone.utc)
        tehran_time = utc_now + timedelta(hours=int(IRAN_UTC_OFFSET), minutes=int((IRAN_UTC_OFFSET % 1) * 60))
        return tehran_time
    
    def _get_current_period(self):
        """Get current period key based on reset time (10:30 AM Iran time)"""
        now = self._get_tehran_time()
        
        if now.hour < RESET_HOUR or (now.hour == RESET_HOUR and now.minute < RESET_MINUTE):
            period_start = now.replace(hour=RESET_HOUR, minute=RESET_MINUTE, second=0, microsecond=0) - timedelta(days=1)
        else:
            period_start = now.replace(hour=RESET_HOUR, minute=RESET_MINUTE, second=0, microsecond=0)
        
        period_key = period_start.strftime("%Y-%m-%d_%H:%M")
        return period_key, period_start
    
    def get_time_until_reset(self):
        """Get time remaining until next reset"""
        now = self._get_tehran_time()
        
        reset_today = now.replace(hour=RESET_HOUR, minute=RESET_MINUTE, second=0, microsecond=0)
        
        if now >= reset_today:
            reset_next = reset_today + timedelta(days=1)
        else:
            reset_next = reset_today
        
        time_left = reset_next - now
        total_seconds = int(time_left.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        
        return hours, minutes, seconds
    
    def load_stats(self):
        """Load statistics from file"""
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    self.stats = json.load(f)
                # چک کردن اینکه فیلدهای لازم وجود دارن
                if "last_period" not in self.stats:
                    self.stats["last_period"] = None
                if "daily_history" not in self.stats:
                    self.stats["daily_history"] = []
                if "total_requests" not in self.stats:
                    self.stats["total_requests"] = 0
                if "today_requests" not in self.stats:
                    self.stats["today_requests"] = 0
            except:
                # اگه فایل خرابه، از نو بساز
                self.stats = {
                    "total_requests": 0,
                    "today_requests": 0,
                    "last_period": None,
                    "daily_history": []
                }
        else:
            self.stats = {
                "total_requests": 0,
                "today_requests": 0,
                "last_period": None,
                "daily_history": []
            }
        
        # Check if period changed
        current_period, _ = self._get_current_period()
        if self.stats["last_period"] != current_period:
            if self.stats["last_period"] is not None:
                self.stats["daily_history"].append({
                    "period": self.stats["last_period"],
                    "count": self.stats["today_requests"]
                })
            self.stats["daily_history"] = self.stats["daily_history"][-30:]
            self.stats["today_requests"] = 0
            self.stats["last_period"] = current_period
        
        self.save_stats()
    
    def save_stats(self):
        """Save statistics to file"""
        try:
            with open(self.filename, 'w') as f:
                json.dump(self.stats, f, indent=2)
        except:
            pass
    
    def increment(self):
        """Increment request counter"""
        self.stats["total_requests"] += 1
        self.stats["today_requests"] += 1
        self.save_stats()
    
    def get_today_count(self):
        """Get today's request count"""
        return self.stats["today_requests"]
    
    def get_total_count(self):
        """Get total request count"""
        return self.stats["total_requests"]
    
    def get_remaining(self, daily_limit=20000):
        """Get remaining requests for today"""
        remaining = daily_limit - self.stats["today_requests"]
        return max(0, remaining)
    
    def get_usage_percent(self, daily_limit=20000):
        """Get usage percentage for today"""
        if daily_limit == 0:
            return 0
        return (self.stats["today_requests"] / daily_limit) * 100
    
    def show_status(self, daily_limit=20000):
        """Show current status with time until reset"""
        remaining = self.get_remaining(daily_limit)
        percent = self.get_usage_percent(daily_limit)
        hours, minutes, seconds = self.get_time_until_reset()
        
        print(f"\n📊 Google Apps Script Usage (resets at {RESET_HOUR:02d}:{RESET_MINUTE:02d} Iran time):")
        print(f"   ├─ Today   : {self.stats['today_requests']:,} / {daily_limit:,}")
        print(f"   ├─ Used    : {percent:.1f}%")
        print(f"   ├─ Left    : {remaining:,}")
        print(f"   └─ Total   : {self.stats['total_requests']:,}")
        print(f"   └─ Reset in: {hours:02d}:{minutes:02d}:{seconds:02d}")
        
        if percent >= 90:
            print(f"\n⚠️  WARNING: {percent:.1f}% of quota used!")
        elif percent >= 75:
            print(f"\n⚡ CAUTION: Close to limit! {percent:.1f}%")
        
        return remaining


# Create global instance
counter = RequestCounter()