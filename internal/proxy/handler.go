package proxy

import (
    "crypto/tls"
    "encoding/binary"
    "encoding/hex"
    "io"
    "net"
    "time"

    "sql-proxy/internal/config"
    "sql-proxy/internal/tds"
    "sql-proxy/internal/tlsmgr"

    "go.uber.org/zap"
)

func HandleConnection(clientPlain net.Conn, cfg *config.Config, logger *zap.Logger) {
    defer clientPlain.Close()
    log := logger.With(zap.String("client", clientPlain.RemoteAddr().String()))
    log.Info("handling connection")

    // 1. Read client Pre-Login
    clientPlain.SetReadDeadline(time.Now().Add(15 * time.Second))
    preBuf := make([]byte, 4096)
    n, err := clientPlain.Read(preBuf)
    if err != nil {
        log.Error("failed to read client pre-login", zap.Error(err))
        return
    }
    preData := preBuf[:n]
    clientEncrypt, _ := tds.ParsePreLogin(preData)
    log.Info("Pre-Login parsed", zap.Uint8("client_encrypt", clientEncrypt),
        zap.String("hex", hex.EncodeToString(preData)))

    // 2. Connect to upstream
    upstreamPlain, err := net.DialTimeout("tcp", cfg.UpstreamAddr, 10*time.Second)
    if err != nil {
        log.Error("failed to connect upstream", zap.Error(err))
        return
    }
    defer upstreamPlain.Close()

    // Forward client Pre-Login to upstream
    if _, err := upstreamPlain.Write(preData); err != nil {
        log.Error("forward pre-login failed", zap.Error(err))
        return
    }

    // Read upstream response
    upstreamPlain.SetReadDeadline(time.Now().Add(10 * time.Second))
    respBuf := make([]byte, 4096)
    n, err = upstreamPlain.Read(respBuf)
    if err != nil {
        log.Error("failed to read upstream pre-login response", zap.Error(err))
        return
    }
    upPreData := respBuf[:n]
    upstreamEncrypt, _ := tds.ParsePreLogin(upPreData)
    log.Info("Upstream Pre-Login", zap.Uint8("upstream_encrypt", upstreamEncrypt),
        zap.String("hex", hex.EncodeToString(upPreData)))

    // 3. Modify response if client wants encryption but upstream doesn't advertise it
    modified := upPreData
    if clientEncrypt != 0 && upstreamEncrypt == 0 {
        var err error
        modified, err = injectEncryptionToken(upPreData, 0x01) // ENCRYPT_ON
        if err != nil {
            log.Error("failed to inject encryption token", zap.Error(err))
            return
        }
        log.Info("injected encryption token into upstream response")
    }

    if _, err := clientPlain.Write(modified); err != nil {
        log.Error("failed to send pre-login response", zap.Error(err))
        return
    }

    // 4. TLS negotiation
    var clientConn net.Conn = clientPlain
    var upstreamConn net.Conn = upstreamPlain

    if clientEncrypt != 0 {
        tlsCfg, err := tlsmgr.NewServerConfig(cfg)
        if err != nil {
            log.Error("TLS config error", zap.Error(err))
            return
        }
        tlsServer := tls.Server(clientPlain, tlsCfg)
        if err := tlsServer.Handshake(); err != nil {
            log.Error("client TLS handshake failed", zap.Error(err))
            return
        }
        clientConn = tlsServer
        log.Info("✅ TLS with client established")
    }

    if upstreamEncrypt != 0 {
        tlsClient := tls.Client(upstreamPlain, &tls.Config{
            InsecureSkipVerify: true,
            MinVersion:         tls.VersionTLS12,
        })
        if err := tlsClient.Handshake(); err != nil {
            log.Error("upstream TLS handshake failed", zap.Error(err))
            return
        }
        upstreamConn = tlsClient
        log.Info("✅ TLS with upstream established")
    }

    clientConn.SetReadDeadline(time.Time{})
    upstreamConn.SetReadDeadline(time.Time{})

    // 5. Forwarding with logging
    parser := tds.NewParser()
    done := make(chan struct{}, 2)

    go func() {
        defer func() { done <- struct{}{} }()
        buf := make([]byte, 64*1024)
        for {
            n, err := clientConn.Read(buf)
            if n > 0 {
                queries := parser.Feed(buf[:n])
                for _, q := range queries {
                    if q != "" {
                        log.Info("SQL Query", zap.String("query", q))
                    }
                }
                if _, werr := upstreamConn.Write(buf[:n]); werr != nil {
                    log.Error("write to upstream failed", zap.Error(werr))
                    return
                }
            }
            if err != nil {
                if err != io.EOF {
                    log.Debug("client read error", zap.Error(err))
                }
                return
            }
        }
    }()

    go func() {
        defer func() { done <- struct{}{} }()
        _, _ = io.Copy(clientConn, upstreamConn)
    }()

    <-done
    <-done
    log.Info("connection finished")
}

func injectEncryptionToken(original []byte, encValue byte) ([]byte, error) {
    if len(original) < 8 {
        return nil, io.ErrUnexpectedEOF
    }
    header := make([]byte, 8)
    copy(header, original[:8])
    payload := original[8:]

    encData := []byte{encValue}
    tokenType := byte(0x01) // ENCRYPTION

    // Build new payload: old payload + token header (5 bytes) + token data (1 byte)
    newPayload := make([]byte, len(payload), len(payload)+5+len(encData))
    copy(newPayload, payload)

    // Absolute offset of token data = header(8) + original payload length + token header(5)
    tokenDataAbsOffset := 8 + len(payload) + 5
    tokenHeader := make([]byte, 5)
    tokenHeader[0] = tokenType
    binary.BigEndian.PutUint16(tokenHeader[1:], uint16(tokenDataAbsOffset))
    binary.BigEndian.PutUint16(tokenHeader[3:], uint16(len(encData)))

    newPayload = append(newPayload, tokenHeader...)
    newPayload = append(newPayload, encData...)

    newLen := 8 + len(newPayload)
    result := make([]byte, 0, newLen)
    result = append(result, header...)
    binary.BigEndian.PutUint16(result[2:4], uint16(newLen))
    result = append(result, newPayload...)
    return result, nil
}