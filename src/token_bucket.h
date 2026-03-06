#ifndef TOKEN_BUCKET_H
#define TOKEN_BUCKET_H

#include "common.h"

// Token Bucket Structure
typedef struct {
    double rate;              // Tokens added per second
    int max_tokens;           // Maximum tokens allowed (immutable after init)
    volatile LONG tokens;     // Current number of tokens (atomic)
    double token_accumulator; // Stores fractional tokens to prevent truncation loss
    volatile LONGLONG last_checked; // Last update time (high precision)
    double freq;              // QueryPerformanceFrequency() value for time conversion
    CRITICAL_SECTION lock;    // Per-bucket lock (protects token_accumulator only)
    bool initialized;         // Flag: true if token_bucket_init succeeded
} TokenBucket;

// Initialize a token bucket. Returns false if parameters are invalid.
bool token_bucket_init(TokenBucket *bucket, double rate, int max_tokens);

// Destroy a token bucket and release its resources.
void token_bucket_destroy(TokenBucket *bucket);

// Replenish tokens based on elapsed time. Thread-safe.
void token_bucket_update(TokenBucket *bucket);

// Returns true if the bucket currently has enough tokens for packet_size bytes.
// Does NOT consume tokens.
bool token_bucket_has_enough_tokens(TokenBucket *bucket, int packet_size);

// Consume packet_size tokens atomically. Calls token_bucket_update internally.
// Returns true on success, false if insufficient tokens.
bool token_bucket_consume(TokenBucket *bucket, int packet_size);

#endif // TOKEN_BUCKET_H
