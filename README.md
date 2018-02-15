docker build -t harbor.whalebone.io/whalebone/agent:testing-1 .

Used envs:
      - WHALEBONE_CLIENT_CRT_BASE64: base64 representation of client certificate
      - WHALEBONE_CLIENT_CRT_BASE64: base64 representation of client private key
      - WHALEBONE_CLIENT_CERT_PASS: certificate password, ("password")
      - LOGGING_LEVEL: optional, if set debug option is enabled, accepts whatever value you supply
      - LOCAL_RESOLVER_ADDRESS: resolver address
      - WHALEBONE_PROXY_ADDRESS: proxy address (wss://wsproxy:8443/wsproxy/ws)
