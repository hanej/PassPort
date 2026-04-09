package idp

import (
	"log/slog"
	"sync"
)

// Registry is a thread-safe registry of live Provider instances.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
	logger    *slog.Logger
}

// NewRegistry creates an empty provider registry.
func NewRegistry(logger *slog.Logger) *Registry {
	return &Registry{
		providers: make(map[string]Provider),
		logger:    logger,
	}
}

// Register adds or replaces a provider in the registry.
func (r *Registry) Register(id string, p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.providers[id] = p
	r.logger.Info("provider registered", "id", id, "type", p.Type())
}

// Unregister removes a provider from the registry.
func (r *Registry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.providers[id]; ok {
		delete(r.providers, id)
		r.logger.Info("provider unregistered", "id", id)
	}
}

// Get returns the provider with the given ID, or false if not found.
func (r *Registry) Get(id string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.providers[id]
	if !ok {
		ids := make([]string, 0, len(r.providers))
		for k := range r.providers {
			ids = append(ids, k)
		}
		r.logger.Debug("provider not found in registry",
			"requested_id", id,
			"registered_ids", ids,
		)
	}
	return p, ok
}

// List returns all registered providers. The returned slice is a snapshot;
// it is safe to iterate without holding the lock.
func (r *Registry) List() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Provider, 0, len(r.providers))
	for _, p := range r.providers {
		result = append(result, p)
	}
	return result
}
