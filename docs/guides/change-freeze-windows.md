# Change-freeze windows

A change-freeze window is a time when scheduled assessments must not start: an end-of-day batch, a month-end close, a
regulatory reporting window. Manage them on the Scheduled Assessments page, under "Change-freeze windows".

## What a window blocks

A window holds every automatic starter that acts on your systems, not only scheduled assessments.

| Starter | During a window | When the window ends |
| --- | --- | --- |
| Scheduled assessments | **Skipped**: the schedule carries on at its next occurrence | Never fires late |
| Attack-path collection (timer) | Held | Runs at the next check, if it is still due |
| API BAS schedules | Held, none is claimed | Each due schedule runs once |
| Ticket revalidation (after a ticket is resolved) | Held, the ticket keeps its flag | The re-run is dispatched |

A held starter asks again every tick, so nothing is lost; its work starts after the window.

Not blocked, on purpose:
- Runs an operator starts by hand, and sweeps an operator starts (they step through techniques one at a time and
  pausing them mid-way would leave them in an odd state).
- Scheduled reports: they read data and send email, and do not act on endpoints.
- Validation of new content on the factory lab agent, and CI validation runs: the lab agent is not a production system.

If the windows cannot be read, the scheduler logs it and starts nothing automatic until they can be read: a read error
never lets a run into a freeze. The log line for a held starter is written once every 15 minutes, not every tick.

The per-agent maintenance freeze (agents page) is a separate feature.

## Two kinds

**Once** covers one start and end, shown in your browser's clock and stored in UTC. Use it for a regulatory reporting
window or a freeze whose dates change every time. Audspect does not ship reporting dates, because they change and
differ by regulator; enter the dates you are given.

**Daily** covers a time range each day, read in the timezone you give (an IANA name such as `Asia/Kolkata`).
- From later than To crosses midnight, for example 22:00 to 06:00.
- To may be `24:00`, the end of the day, so a window can cover whole days.
- Optionally limit it to dates (applies from / to), to weekdays, or to days of the month.

### Weekdays and days of the month

Both filters read the day the window **starts**, in the window's timezone. The hours after midnight of an overnight
window belong to the day it started: a Friday 22:00 to 06:00 window covers Saturday until 06:00.

- Weekdays: tick the days. None ticked means every day.
- Days of the month: a list such as `-2,-1,1`. A positive number is that day of the month; a negative number counts from
  the end, so `-1` is the last day and `-2` the one before it, correct for 28, 29, 30 and 31 day months.

## Presets

Presets fill the form as a starting point. Change anything, and set your timezone: a preset never picks it.

| Preset | Fills |
| --- | --- |
| End-of-day batch | Mon to Fri, 18:00 to 23:00 |
| Beginning-of-day batch | Mon to Fri, 05:00 to 09:00 |
| Month-end | every day 00:00 to 24:00, on days `-2,-1,1` |
| Regulatory reporting window | a once window; you set the dates |

The times are common defaults, not your bank's. Match them to your own batch schedule.

## API

`GET /api/scheduled-blackouts`, `POST /api/scheduled-blackouts`, `DELETE /api/scheduled-blackouts/{id}`, for admin and
analyst. A daily window is posted as `{"name","kind":"daily","timeFrom","timeTo","timezone","weekdays":"mon,tue",
"monthDays":"-2,-1,1","validFrom","validTo"}`; the filters and dates are optional. A window the server cannot read
correctly is refused with 400 and a reason.
