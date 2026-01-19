
/*
* Copyright (C)
* Filename: time_nosc.c
* Author:
* yisong <songyi.sy@alibaba-inc.com>
* Description: this file export gmtime_r_nosc(), gmtime_r_nosc() is used in dataplane.
*              gmtime_r_nosc() removes syscall in gmtime_r(), which come from glibc-2.20
*/

#include <errno.h>
#include <time.h>
#include <stdio.h>

#define SECSPERMIN	60
#define MINSPERHOUR	60
#define HOURSPERDAY	24

#define SECSPERHOUR	(SECSPERMIN * MINSPERHOUR)
typedef long int int_fast32_t;
#define SECSPERDAY	((int_fast32_t) SECSPERHOUR * HOURSPERDAY)

#define	SECS_PER_HOUR	(60 * 60)
#define	SECS_PER_DAY	(SECS_PER_HOUR * 24)

/* This structure contains all the information about a
   timezone given in the POSIX standard TZ envariable.  */
typedef struct {
    const char *name;

    /* When to change.  */
    enum { J0, J1, M } type;    /* Interpretation of:  */
    unsigned short int m, n, d; /* Month, week, day.  */
    int secs;                   /* Time of day.  */

    long int offset;            /* Seconds east of GMT (west if < 0).  */

    /* We cache the computed time of change for a
       given year so we don't have to recompute it.  */
    time_t change;              /* When to change to this zone.  */
    int computed_for;           /* Year above is computed for.  */
} tz_rule;

const unsigned short int __mon_yday[2][13] = {
    /* Normal years.  */
    {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365},
    /* Leap years.  */
    {0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366}
};

/* Compute the `struct tm' representation of *T,
   offset OFFSET seconds east of UTC,
   and store year, yday, mon, mday, wday, hour, min, sec into *TP.
   Return nonzero if successful.  */
int __offtime(t, offset, tp)
const time_t *t;
long int offset;
struct tm *tp;
{
    time_t days, rem, y;
    const unsigned short int *ip;

    days = *t / SECS_PER_DAY;
    rem = *t % SECS_PER_DAY;
    rem += offset;
    while (rem < 0) {
        rem += SECS_PER_DAY;
        --days;
    }
    while (rem >= SECS_PER_DAY) {
        rem -= SECS_PER_DAY;
        ++days;
    }
    tp->tm_hour = rem / SECS_PER_HOUR;
    rem %= SECS_PER_HOUR;
    tp->tm_min = rem / 60;
    tp->tm_sec = rem % 60;
    /* January 1, 1970 was a Thursday.  */
    tp->tm_wday = (4 + days) % 7;
    if (tp->tm_wday < 0)
        tp->tm_wday += 7;
    y = 1970;

#define DIV(a, b) ((a) / (b) - ((a) % (b) < 0))
#define LEAPS_THRU_END_OF(y) (DIV (y, 4) - DIV (y, 100) + DIV (y, 400))

    while (days < 0 || days >= (__isleap(y) ? 366 : 365)) {
        /* Guess a corrected year, assuming 365 days per year.  */
        time_t yg = y + days / 365 - (days % 365 < 0);

        /* Adjust DAYS and Y to match the guessed year.  */
        days -= ((yg - y) * 365 + LEAPS_THRU_END_OF(yg - 1)
                 - LEAPS_THRU_END_OF(y - 1));
        y = yg;
    }
    tp->tm_year = y - 1900;
    if (tp->tm_year != y - 1900) {
        /* The year cannot be represented due to overflow.  */
        return 0;
    }
    tp->tm_yday = days;
    ip = __mon_yday[__isleap(y)];
    for (y = 11; days < (long int)ip[y]; --y)
        continue;
    days -= ip[y];
    tp->tm_mon = y;
    tp->tm_mday = days + 1;
    return 1;
}

/* Figure out the exact time (as a time_t) in YEAR
   when the change described by RULE will occur and
   put it in RULE->change, saving YEAR in RULE->computed_for.  */
static void compute_change(rule, year)
tz_rule *rule;
int year;
{
    time_t t;

    if (year != -1 && rule->computed_for == year)
        /* Operations on times in 2 BC will be slower.  Oh well.  */
        return;

    /* First set T to January 1st, 0:00:00 GMT in YEAR.  */
    if (year > 1970)
        t = ((year - 1970) * 365 +  /* Compute the number of leapdays between 1970 and YEAR
                                       (exclusive).  There is a leapday every 4th year ...  */
             +((year - 1) / 4 - 1970 / 4)
             /* ... except every 100th year ... */
             - ((year - 1) / 100 - 1970 / 100)
             /* ... but still every 400th year.  */
             + ((year - 1) / 400 - 1970 / 400)) * SECSPERDAY;
    else
        t = 0;

    switch (rule->type) {
        case J1:
            /* Jn - Julian day, 1 == January 1, 60 == March 1 even in leap years.
               In non-leap years, or if the day number is 59 or less, just
               add SECSPERDAY times the day number-1 to the time of
               January 1, midnight, to get the day.  */
            t += (rule->d - 1) * SECSPERDAY;
            if (rule->d >= 60 && __isleap(year))
                t += SECSPERDAY;
            break;

        case J0:
            /* n - Day of year.
               Just add SECSPERDAY times the day number to the time of Jan 1st.  */
            t += rule->d * SECSPERDAY;
            break;

        case M:
            /* Mm.n.d - Nth "Dth day" of month M.  */
            {
                unsigned int i;
                int d, m1, yy0, yy1, yy2, dow;
                const unsigned short int *myday =
                    &__mon_yday[__isleap(year)][rule->m];

                /* First add SECSPERDAY for each day in months before M.  */
                t += myday[-1] * SECSPERDAY;

                /* Use Zeller's Congruence to get day-of-week of first day of month. */
                m1 = (rule->m + 9) % 12 + 1;
                yy0 = (rule->m <= 2) ? (year - 1) : year;
                yy1 = yy0 / 100;
                yy2 = yy0 % 100;
                dow =
                    ((26 * m1 - 2) / 10 + 1 + yy2 + yy2 / 4 + yy1 / 4 -
                     2 * yy1) % 7;
                if (dow < 0)
                    dow += 7;

                /* DOW is the day-of-week of the first day of the month.  Get the
                   day-of-month (zero-origin) of the first DOW day of the month.  */
                d = rule->d - dow;
                if (d < 0)
                    d += 7;
                for (i = 1; i < rule->n; ++i) {
                    if (d + 7 >= (int)myday[0] - myday[-1])
                        break;
                    d += 7;
                }

                /* D is the day-of-month (zero-origin) of the day we want.  */
                t += d * SECSPERDAY;
            }
            break;
    }

    /* T is now the Epoch-relative time of 0:00:00 GMT on the day we want.
       Just add the time of day and local offset from GMT, and we're done.  */

    rule->change = t - rule->offset + rule->secs;
    rule->computed_for = year;
}

static tz_rule tz_rules[2];

/* Figure out the correct timezone for TM and set `__tzname',
   `__timezone', and `__daylight' accordingly.  */
void __tz_compute(timer, tm, use_localtime)
time_t timer;
struct tm *tm;
int use_localtime;
{
    compute_change(&tz_rules[0], 1900 + tm->tm_year);
    compute_change(&tz_rules[1], 1900 + tm->tm_year);

    if (use_localtime) {
        int isdst;

        /* We have to distinguish between northern and southern
           hemisphere.  For the latter the daylight saving time
           ends in the next year.  */
        if (__builtin_expect(tz_rules[0].change > tz_rules[1].change, 0))
            isdst = (timer < tz_rules[1].change || timer >= tz_rules[0].change);
        else
            isdst = (timer >= tz_rules[0].change && timer < tz_rules[1].change);
        tm->tm_isdst = isdst;
        tm->tm_zone = __tzname[isdst];
        tm->tm_gmtoff = tz_rules[isdst].offset;
    }
}

/* Return the `struct tm' representation of *TIMER in the local timezone.
   Use local time if USE_LOCALTIME is nonzero, UTC otherwise.  */
struct tm *__tz_convert(const time_t * timer, int use_localtime, struct tm *tp)
{
    long int leap_correction;
    int leap_extra_secs;

    if (timer == NULL) {
        return NULL;
    }

    /* Update internal database according to current TZ setting.
       POSIX.1 8.3.7.2 says that localtime_r is not required to set tzname.
       This is a good idea since this allows at least a bit more parallelism.  */
    //tzset_internal (tp == &_tmbuf && use_localtime, 1);

    if (!__offtime(timer, 0, tp))
        tp = NULL;
    else
        __tz_compute(*timer, tp, use_localtime);
    leap_correction = 0L;
    leap_extra_secs = 0;

    if (tp) {
        if (!use_localtime) {
            tp->tm_isdst = 0;
            tp->tm_zone = "GMT";
            tp->tm_gmtoff = 0L;
        }

        if (__offtime(timer, tp->tm_gmtoff - leap_correction, tp))
            tp->tm_sec += leap_extra_secs;
        else
            tp = NULL;
    }

    return tp;
}

/* Return the `struct tm' representation of *T in UTC,
   using *TP to store the result.  */
struct tm *gmtime_r_nosc(t, tp)
const time_t *t;
struct tm *tp;
{
    return __tz_convert(t, 0, tp);
}
