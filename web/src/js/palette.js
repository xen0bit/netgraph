// The command palette's pure parts: reading a time out of what someone typed,
// and matching a command. Exported on their own so tests can feed them directly.
import { units, stamp } from "./util.js";

const wordUnits = { s: "s", sec: "s", secs: "s", second: "s", seconds: "s", m: "m", min: "m", mins: "m", minute: "m", minutes: "m",
  h: "h", hr: "h", hrs: "h", hour: "h", hours: "h", d: "d", day: "d", days: "d", w: "w", wk: "w", wks: "w", week: "w", weeks: "w" };
const unitName = { s: "second", m: "minute", h: "hour", d: "day", w: "week" };
const weekdays = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];

// clockOf reads "3pm", "3:30 pm", "15:00" or "9". null if it isn't a time.
function clockOf(s) {
  const m = /^(\d{1,2})(?::(\d{2}))?\s*(am|pm)?$/.exec(s.trim());
  if (!m) return null;
  let h = Number(m[1]);
  const min = Number(m[2] || 0);
  if (min > 59 || h > 23) return null;
  if (m[3]) {
    if (h < 1 || h > 12) return null;
    h = (h % 12) + (m[3] === "pm" ? 12 : 0);
  } else if (!m[2] && h > 23) return null;
  return [h, min];
}

const startOfDay = (ms) => { const d = new Date(ms); d.setHours(0, 0, 0, 0); return d; };
const addDays = (d, n) => { const c = new Date(d); c.setDate(c.getDate() + n); return c; };
const at = (d, [h, min]) => { const c = new Date(d); c.setHours(h, min, 0, 0); return c.getTime(); };

// A moment opens the hour around it; a whole day opens that day.
const moment = (ms, label) => ({ to: ms + units.h / 2, span: units.h, label });
const wholeDay = (d, label) => ({ to: addDays(d, 1).getTime(), span: addDays(d, 1).getTime() - d.getTime(), label });

// parseWhen turns typed text into a window {to, span, label, live}, or null.
export function parseWhen(text, now = Date.now()) {
  const s = String(text).trim().toLowerCase().replace(/\s+/g, " ");
  if (!s) return null;
  let m = /^(?:(?:last|past) )?(\d+(?:\.\d+)?) ?([a-z]+)( ago)?$/.exec(s);
  if (m && wordUnits[m[2]]) {
    const u = wordUnits[m[2]], n = Number(m[1]);
    if (n <= 0) return null;
    const name = `${n} ${unitName[u]}${n === 1 ? "" : "s"}`;
    if (m[3]) return moment(now - n * units[u], `${name} ago`);
    return { to: now, span: n * units[u], label: `The last ${name}`, live: true };
  }
  m = /^(today|yesterday|sunday|monday|tuesday|wednesday|thursday|friday|saturday)(?:(?: at)? (.+))?$/.exec(s);
  if (m) {
    const today = startOfDay(now);
    let day;
    if (m[1] === "today") day = today;
    else if (m[1] === "yesterday") day = addDays(today, -1);
    else {
      // The most recent one: never today, which has its own word.
      const back = ((today.getDay() - weekdays.indexOf(m[1]) + 7) % 7) || 7;
      day = addDays(today, -back);
    }
    if (!m[2]) return wholeDay(day, m[1][0].toUpperCase() + m[1].slice(1));
    const c = clockOf(m[2]);
    if (!c) return null;
    const ms = at(day, c);
    return moment(ms, stamp(ms));
  }
  m = /^(\d{4})-(\d{2})-(\d{2})(?:[ t](.+))?$/.exec(s);
  if (m) {
    const day = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
    if (day.getMonth() !== Number(m[2]) - 1 || day.getDate() !== Number(m[3])) return null;
    if (!m[4]) return wholeDay(day, s);
    const c = clockOf(m[4].replace(/:\d{2}$/, (x) => (/^\d{1,2}:\d{2}:\d{2}$/.test(m[4]) ? "" : x)));
    if (!c) return null;
    const ms = at(day, c);
    return moment(ms, stamp(ms));
  }
  // A bare time needs am/pm or a colon: "15" is not obviously a time.
  if (/(am|pm|:)/.test(s)) {
    const c = clockOf(s);
    if (!c) return null;
    let ms = at(startOfDay(now), c);
    if (ms > now) ms = at(addDays(startOfDay(now), -1), c);
    return moment(ms, stamp(ms));
  }
  return null;
}

// fuzzy scores how well a query matches a label: its letters in order, better
// when they are together and at the start of a word. 0 means no match.
export function fuzzy(q, label) {
  q = q.toLowerCase();
  const l = label.toLowerCase();
  if (!q) return 1;
  let score = 0, from = 0, last = -2;
  for (const ch of q) {
    if (ch === " ") continue;
    const i = l.indexOf(ch, from);
    if (i < 0) return 0;
    score += 1;
    if (i === last + 1) score += 3;
    if (i === 0 || l[i - 1] === " ") score += 2;
    last = i;
    from = i + 1;
  }
  return score - l.length / 100;
}
