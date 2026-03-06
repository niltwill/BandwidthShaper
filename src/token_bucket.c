// token_bucket.c
// Token bucket rate limiter implementation.

#include "token_bucket.h"

// --------------------------------------------------------------------------
// Public API
// --------------------------------------------------------------------------

bool token_bucket_init(TokenBucket *bucket, double rate, int max_tokens) {
    if (!bucket || rate <= 0 || max_tokens <= 0) return false;

    bucket->rate = rate;
    bucket->max_tokens = max_tokens;
    bucket->tokens = max_tokens;
    bucket->token_accumulator = 0.0;

    LARGE_INTEGER freq;
    QueryPerformanceFrequency(&freq);
    bucket->freq = (double)freq.QuadPart;
    bucket->last_checked = get_time_ticks();

    InitializeCriticalSection(&bucket->lock);
    bucket->initialized = true;
    return true;
}

void token_bucket_destroy(TokenBucket *bucket) {
    if (bucket && bucket->initialized) {
        DeleteCriticalSection(&bucket->lock);
        bucket->initialized = false;
    }
}

// Replenish tokens based on elapsed time.
// Thread-safe: uses atomic compare-exchange so only one thread wins the race
// to claim each time window, then adds the calculated tokens atomically.
// Threads that lose the race will skip token addition for that window.
void token_bucket_update(TokenBucket *bucket) {
    if (!bucket || bucket->rate <= 0) return;

    LONGLONG now = get_time_ticks();
    LONGLONG last;
    LONGLONG elapsed_ticks;

    // Attempt to claim this time window for token replenishment
    do {
        last = InterlockedCompareExchange64(&bucket->last_checked, 0, 0);
        elapsed_ticks = now - last;
        if (elapsed_ticks <= 0) return; // No time elapsed or clock went backwards
    } while (InterlockedCompareExchange64(&bucket->last_checked, now, last) != last);

    // We successfully claimed this time window - calculate tokens to add
    double elapsed_seconds = (double)elapsed_ticks / bucket->freq;
    double tokens_to_add = bucket->rate * elapsed_seconds;

    // Accumulate fractional tokens under lock to prevent precision loss
    // The lock only protects token_accumulator, not tokens (which is atomic)
    EnterCriticalSection(&bucket->lock);
    bucket->token_accumulator += tokens_to_add;

    // Cap the accumulator to prevent unbounded growth in case of prolonged
    // inactivity. The 2x multiplier allows some headroom for fractional
    // accumulation while preventing overflow. max_tokens is immutable after
    // init, so safe to read without lock.
    if (bucket->token_accumulator > bucket->max_tokens * 2) {
        bucket->token_accumulator = bucket->max_tokens;
    }
    int whole_tokens = (int)bucket->token_accumulator;
    bucket->token_accumulator -= whole_tokens;
    LeaveCriticalSection(&bucket->lock);

    // Add whole tokens without exceeding max_tokens (atomic CAS loop)
    LONG current_tokens, new_tokens;
    do {
        current_tokens = bucket->tokens;
        new_tokens = current_tokens + whole_tokens;
        if (new_tokens > bucket->max_tokens) new_tokens = bucket->max_tokens;
        if (new_tokens < 0) new_tokens = 0;  // Safety clamp
    } while (InterlockedCompareExchange(&bucket->tokens, new_tokens, current_tokens) != current_tokens);
}

bool token_bucket_has_enough_tokens(TokenBucket *bucket, int packet_size) {
    return bucket->tokens >= packet_size;
}

bool token_bucket_consume(TokenBucket *bucket, int packet_size) {
    if (!bucket || packet_size <= 0) return false;

    if ((size_t)packet_size > (size_t)INT_MAX / 2) {
        fprintf(stderr, "Error: Packet size too large for token bucket: %d\n", packet_size);
        return false;
    }

    // Replenish tokens first. Note: If multiple threads call consume
    // simultaneously, only one will actually add tokens for each time window.
    // Others will see elapsed_ticks <= 0 and return early without adding
    // tokens. This is correct - tokens should only be added once per
    // elapsed time period, regardless of how many threads attempt consumes.
    token_bucket_update(bucket);

    LONG old_tokens, new_tokens;
    do {
        old_tokens = bucket->tokens;

        if (old_tokens < 0 || (size_t)old_tokens < (size_t)packet_size)
            return false; // Not enough tokens

        new_tokens = old_tokens - packet_size;

        if (new_tokens < 0 || new_tokens > bucket->max_tokens)
            return false; // Would create invalid state

    } while (InterlockedCompareExchange(&bucket->tokens, new_tokens, old_tokens) != old_tokens);

    return true;
}
