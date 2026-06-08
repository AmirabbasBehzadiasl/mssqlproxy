package proxy

import (
	"net"
	"sync"

	"sql-proxy/internal/config"   

	"go.uber.org/zap"
)

type Server struct {
	cfg      *config.Config
	listener net.Listener
	wg       sync.WaitGroup
	logger   *zap.Logger
}

func NewServer(cfg *config.Config, logger *zap.Logger) *Server {
	return &Server{
		cfg:    cfg,
		logger: logger,
	}
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		s.logger.Error("failed to start listener", zap.Error(err))
		return err
	}
	s.listener = ln
	s.logger.Info("proxy listening", zap.String("addr", s.cfg.ListenAddr))

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.logger.Info("listener closed", zap.Error(err))
			return err
		}

		s.wg.Add(1)
		s.logger.Info("new connection accepted", zap.String("client", conn.RemoteAddr().String()))

		go func(c net.Conn) {
			defer s.wg.Done()
			HandleConnection(c, s.cfg, s.logger)
		}(conn)
	}
}