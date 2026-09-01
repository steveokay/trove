package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"

	"github.com/steveokay/trove/internal/config"
)

// Server owns the HTTP listener and the process's claim on the data
// directory. It is constructed once and run once.
type Server struct {
	cfg  *config.Config
	log  *slog.Logger
	http *http.Server
	lock *DataDirLock

	// ready is closed once the listener is bound and addr is set. Callers wait
	// on it rather than polling, which is both race-free and deterministic.
	ready chan struct{}

	mu sync.Mutex
	// addr is the resolved listen address, known only after binding. Guarded
	// because Run and its caller are on different goroutines by construction.
	addr net.Addr
}

// New builds a server for the given handler. It does not bind or lock
// anything; that happens in Run.
func New(cfg *config.Config, log *slog.Logger, handler http.Handler) *Server {
	wrapped := WithRequestLogging(log, nil)(handler)

	return &Server{
		cfg:   cfg,
		log:   log,
		ready: make(chan struct{}),
		http: &http.Server{
			Addr:              cfg.Server.Address,
			Handler:           wrapped,
			ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout.Std(),
			ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		},
	}
}

// Addr reports the address the server is listening on, or nil before Run has
// bound it. Wait on Ready first if you need it to be set.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// Ready is closed once the server is listening and Addr is populated. It never
// closes if Run fails before binding, so wait on it alongside Run's error --
// never on its own. A Server runs once, so Ready closes at most once.
func (s *Server) Ready() <-chan struct{} { return s.ready }

// Run acquires the data directory lock, serves until ctx is cancelled, then
// drains in-flight requests within the configured grace period. It returns nil
// on a clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	lock, err := AcquireDataDirLock(s.cfg.DataDir)
	if err != nil {
		return err
	}
	s.lock = lock
	defer func() {
		if err := s.lock.Release(); err != nil {
			s.log.Warn("releasing data directory lock", slog.String("error", err.Error()))
		}
	}()

	listener, err := net.Listen("tcp", s.cfg.Server.Address)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.cfg.Server.Address, err)
	}
	s.mu.Lock()
	s.addr = listener.Addr()
	addr := s.addr
	s.mu.Unlock()
	close(s.ready)

	s.log.Info("serving",
		slog.String("address", addr.String()),
		slog.String("data_dir", s.cfg.DataDir),
	)

	serveErr := make(chan error, 1)
	go func() {
		err := s.http.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}

	return s.shutdown(serveErr)
}

// shutdown drains in-flight requests, then waits for Serve to return.
func (s *Server) shutdown(serveErr <-chan error) error {
	grace := s.cfg.Server.ShutdownGrace.Std()
	s.log.Info("shutting down", slog.Duration("grace", grace))

	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()

	err := s.http.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		// Requests outlived the grace period. Closing is the honest end of a
		// graceful shutdown: report it rather than hanging.
		s.log.Warn("grace period expired with requests in flight; closing connections",
			slog.Duration("grace", grace))
		if closeErr := s.http.Close(); closeErr != nil {
			s.log.Warn("closing listener", slog.String("error", closeErr.Error()))
		}
	} else if err != nil {
		return fmt.Errorf("shutting down: %w", err)
	}

	if serveErr := <-serveErr; serveErr != nil {
		return serveErr
	}

	s.log.Info("stopped")
	return nil
}
