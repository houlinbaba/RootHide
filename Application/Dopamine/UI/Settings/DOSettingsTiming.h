#ifndef DO_SETTINGS_TIMING_H
#define DO_SETTINGS_TIMING_H

#include <math.h>
#include <stdint.h>
#include <time.h>

// Main-thread elapsed time only. Nested categories overlap; this is not FPS
// or a measurement of render-server/GPU work. No allocation or I/O per sample.
enum DOSettingsTimingKind {
    DOSettingsTimingBackdrop,
    DOSettingsTimingMaterial,
    DOSettingsTimingCell,
    DOSettingsTimingHairlines,
    DOSettingsTimingLayout,
    DOSettingsTimingKindCount
};

struct DOSettingsTimingSample {
    uint64_t calls, over8ms, over16ms;
    double total, maximum;
};

struct DOSettingsTiming {
    struct DOSettingsTimingSample samples[2][DOSettingsTimingKindCount];
};

static inline double DOSettingsTimingNow(void)
{
    struct timespec value = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return (double)value.tv_sec + (double)value.tv_nsec / 1000000000.0;
}

static inline void DOSettingsTimingRecord(struct DOSettingsTiming *timing,
    enum DOSettingsTimingKind kind, int scrolling, double start, double end)
{
    if (!timing || kind < 0 || kind >= DOSettingsTimingKindCount ||
        start <= 0 || end < start || !isfinite(start) || !isfinite(end)) return;
    double elapsed = end - start;
    struct DOSettingsTimingSample *sample = &timing->samples[scrolling != 0][kind];
    sample->calls++;
    sample->total += elapsed;
    if (elapsed > sample->maximum) sample->maximum = elapsed;
    if (elapsed > 1.0 / 120.0) sample->over8ms++;
    if (elapsed > 1.0 / 60.0) sample->over16ms++;
}

#endif
