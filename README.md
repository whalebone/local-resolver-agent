docker build -t harbor.whalebone.io/whalebone/agent:testing-1 .

Used envs:
- WHALEBONE_CLIENT_CRT_BASE64: base64 representation of client certificate
- WHALEBONE_CLIENT_CRT_BASE64: base64 representation of client private key
- WHALEBONE_PROXY_ADDRESS: proxy address (wss://wsproxy:8443/wsproxy/ws)
- LOGGING_LEVEL: (optional) if set debug option is enabled, accepts whatever value you supply
- LOCAL_RESOLVER_ADDRESS: (optional) resolver address, if not set localhost is used
- PERIODIC_INTERVAL: (optional) sets period in seconds for periodic functions sending (sysinfo), if not set default value of 30 seconds will be used
