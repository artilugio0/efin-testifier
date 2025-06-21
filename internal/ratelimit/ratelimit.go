package ratelimit

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimitedClient wraps an http.Client with rate limiting.
type RateLimitedClient struct {
	client     *http.Client
	limiter    *rate.Limiter
	reserveMux sync.Mutex
}

// NewRateLimitedClient creates a new RateLimitedClient with the given requests per second limit.
func NewRateLimitedClient(client *http.Client, requestsPerSecond float64) *RateLimitedClient {
	// Create a limiter allowing requestsPerSecond tokens per second, with a burst size equal to the limit.
	limiter := rate.NewLimiter(rate.Limit(requestsPerSecond), int(requestsPerSecond))
	return &RateLimitedClient{
		client:  client,
		limiter: limiter,
	}
}

// Do performs an HTTP request with rate limiting.
func (c *RateLimitedClient) Do(req *http.Request) (*http.Response, error) {
	// Reserve a token, waiting if necessary.
	c.reserveMux.Lock()
	ctx := req.Context()
	reservation := c.limiter.Reserve()
	delay := reservation.Delay()
	c.reserveMux.Unlock()

	// Wait for the delay if any.
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// Perform the request using the underlying client.
	return c.client.Do(req)
}
