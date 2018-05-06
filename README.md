docker build -t whalebone/agent:testing-1 .

##### Agent envs:
- WHALEBONE_CLIENT_CRT_BASE64: base64 representation of client certificate
- WHALEBONE_CLIENT_CRT_BASE64: base64 representation of client private key
- WHALEBONE_PROXY_ADDRESS: proxy address (wss://wsproxy:8443/wsproxy/ws)
- LOGGING_LEVEL: (optional) if set debug option is enabled, accepts whatever value you supply
- LOCAL_RESOLVER_ADDRESS: (optional) resolver address, if not set localhost is used
- PERIODIC_INTERVAL: (optional) sets period in seconds for periodic functions sending (sysinfo), if not set default value of 30 seconds will be used
- KRESMAN_LISTENER: (optional) sets kresman listener for cache, if not set 'http:localhost:8080' is used

##### Messages:

Message fields are: '**requestId**', '**data**', '**action**'.
Data and action are always present, requestId is present only when the message way initiated by portal, messages initiated by agent don't have them.
. Portal only receives what is in the key '**data**'. Data key needs to be decoded/encoded to BASE64 upon receiving/sending for Wsproxy compatibility,

Sample message from agent:
'''json
{"requestId": '4as6c4as6d4wf', "action": create,
                    "data": {"status": "failure", "message": "failed to parse/decode request", "body": "some text"}}       
'''


##### Used volumes:
- /var/run/docker.sock : /var/run/docker.sock - to access docker api
- /var/log/whalebone/ : /etc/whalebone/log/ - to access resolver log file
- /etc/whalebone/resolver/ : /etc/whalebone/kres/ - to save resolver config 
- /var/log/whalebone/agent/ : /etc/whalebone/logs/ - to expose its own logs

##### Useful Directories:
- /opt/whalebone/ - code is stored here and in certs/ are cert and key files
- /etc/whalebone/compose - resolver docker-compose is here
- /etc/whalebone/logs - agent logs are here
- /etc/whalebone/log - resolver log is mounted here
- /etc/whalebone/kres - resolver config si stored here and exposed to the world