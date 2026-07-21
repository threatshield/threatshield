// World-clock timezone list + timezone-aware date formatting helpers.
//
// Backend stores assessment timestamps as UTC ISO strings *without* a `Z`
// suffix (e.g. "2026-06-24T10:30:45.123456"). JS `new Date(...)` would parse
// those as local time, displaying the wrong hour. `parseAsUtc` fixes that, and
// the formatters render in an admin-configured IANA timezone.

export const DEFAULT_TIMEZONE = 'Asia/Kolkata';

export interface WorldClockZone {
  /** IANA timezone identifier, e.g. "America/New_York". */
  value: string;
  /** Human-readable city / region label. */
  label: string;
  /** Approximate UTC offset label for display (does not track DST). */
  offset: string;
}

// Curated world-clock list of major cities, ordered roughly west → east.
export const WORLD_CLOCK_ZONES: WorldClockZone[] = [
  { value: 'Pacific/Midway', label: 'Midway Island', offset: 'UTC−11:00' },
  { value: 'Pacific/Honolulu', label: 'Honolulu', offset: 'UTC−10:00' },
  { value: 'America/Anchorage', label: 'Anchorage', offset: 'UTC−09:00' },
  { value: 'America/Los_Angeles', label: 'Los Angeles', offset: 'UTC−08:00' },
  { value: 'America/Denver', label: 'Denver', offset: 'UTC−07:00' },
  { value: 'America/Chicago', label: 'Chicago', offset: 'UTC−06:00' },
  { value: 'America/Mexico_City', label: 'Mexico City', offset: 'UTC−06:00' },
  { value: 'America/New_York', label: 'New York', offset: 'UTC−05:00' },
  { value: 'America/Bogota', label: 'Bogotá', offset: 'UTC−05:00' },
  { value: 'America/Caracas', label: 'Caracas', offset: 'UTC−04:00' },
  { value: 'America/Sao_Paulo', label: 'São Paulo', offset: 'UTC−03:00' },
  { value: 'Atlantic/Azores', label: 'Azores', offset: 'UTC−01:00' },
  { value: 'UTC', label: 'UTC', offset: 'UTC±00:00' },
  { value: 'Europe/London', label: 'London', offset: 'UTC+00:00' },
  { value: 'Europe/Paris', label: 'Paris', offset: 'UTC+01:00' },
  { value: 'Europe/Berlin', label: 'Berlin', offset: 'UTC+01:00' },
  { value: 'Europe/Madrid', label: 'Madrid', offset: 'UTC+01:00' },
  { value: 'Africa/Lagos', label: 'Lagos', offset: 'UTC+01:00' },
  { value: 'Europe/Athens', label: 'Athens', offset: 'UTC+02:00' },
  { value: 'Africa/Cairo', label: 'Cairo', offset: 'UTC+02:00' },
  { value: 'Africa/Johannesburg', label: 'Johannesburg', offset: 'UTC+02:00' },
  { value: 'Europe/Moscow', label: 'Moscow', offset: 'UTC+03:00' },
  { value: 'Asia/Riyadh', label: 'Riyadh', offset: 'UTC+03:00' },
  { value: 'Asia/Tehran', label: 'Tehran', offset: 'UTC+03:30' },
  { value: 'Asia/Dubai', label: 'Dubai', offset: 'UTC+04:00' },
  { value: 'Asia/Karachi', label: 'Karachi', offset: 'UTC+05:00' },
  { value: 'Asia/Kolkata', label: 'India (Mumbai / Bengaluru)', offset: 'UTC+05:30' },
  { value: 'Asia/Kathmandu', label: 'Kathmandu', offset: 'UTC+05:45' },
  { value: 'Asia/Dhaka', label: 'Dhaka', offset: 'UTC+06:00' },
  { value: 'Asia/Bangkok', label: 'Bangkok', offset: 'UTC+07:00' },
  { value: 'Asia/Singapore', label: 'Singapore', offset: 'UTC+08:00' },
  { value: 'Asia/Shanghai', label: 'Shanghai', offset: 'UTC+08:00' },
  { value: 'Asia/Hong_Kong', label: 'Hong Kong', offset: 'UTC+08:00' },
  { value: 'Asia/Tokyo', label: 'Tokyo', offset: 'UTC+09:00' },
  { value: 'Asia/Seoul', label: 'Seoul', offset: 'UTC+09:00' },
  { value: 'Australia/Sydney', label: 'Sydney', offset: 'UTC+10:00' },
  { value: 'Pacific/Auckland', label: 'Auckland', offset: 'UTC+12:00' },
];

const TZ_DESIGNATOR = /([zZ]|[+-]\d{2}:?\d{2})$/;

/**
 * Parse a server timestamp. Strings with no timezone designator are treated as
 * UTC (the backend writes naive UTC via `datetime.utcnow().isoformat()`).
 */
export function parseAsUtc(dateString: string): Date {
  if (typeof dateString === 'string' && dateString.includes('T') && !TZ_DESIGNATOR.test(dateString)) {
    return new Date(`${dateString}Z`);
  }
  return new Date(dateString);
}

function dayKey(date: Date, timeZone?: string): string {
  // en-CA yields YYYY-MM-DD, ideal for comparing calendar days within a tz.
  return date.toLocaleDateString('en-CA', timeZone ? { timeZone } : undefined);
}

/**
 * Format a server timestamp into a relative label (e.g. "Today, 4:00 PM",
 * "Yesterday", "3d ago") and a full label, both in the given timezone.
 */
export function formatTimestamp(
  dateString: string,
  timeZone?: string,
): { relative: string; full: string } {
  try {
    const date = parseAsUtc(dateString);
    if (isNaN(date.getTime())) return { relative: '—', full: '' };
    const now = new Date();
    const tzOpt = timeZone ? { timeZone } : {};

    const todayKey = dayKey(now, timeZone);
    const yesterdayKey = dayKey(new Date(now.getTime() - 86400000), timeZone);
    const thatKey = dayKey(date, timeZone);
    const diffDays = Math.floor((now.getTime() - date.getTime()) / 86400000);

    let relative: string;
    if (thatKey === todayKey) {
      relative = `Today, ${date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', ...tzOpt })}`;
    } else if (thatKey === yesterdayKey) {
      relative = 'Yesterday';
    } else if (diffDays >= 0 && diffDays < 7) {
      relative = `${diffDays}d ago`;
    } else {
      relative = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', ...tzOpt });
    }

    const full = date.toLocaleString('en-US', {
      month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit',
      ...tzOpt,
      timeZoneName: 'short',
    });
    return { relative, full };
  } catch {
    return { relative: '—', full: '' };
  }
}
