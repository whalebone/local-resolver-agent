docker build -t whalebone/agent:1.x.x .

Docs:
----------
[Docs](https://github.com/whalebone/wsproxy/wiki)

Agent envs:
----------
- CLIENT_CRT_BASE64: base64 representation of client certificate
- CLIENT_KEY_BASE64: base64 representation of client private key
- PROXY_ADDRESS: proxy address (wss://wsproxy:8443/wsproxy/ws)
- LOGGING_LEVEL: (optional) if set debug option is enabled, accepts whatever value you supply
- LOCAL_RESOLVER_ADDRESS: (optional) resolver address, if not set localhost is used
- PERIODIC_INTERVAL: (optional) sets period in seconds for periodic functions sending (sysinfo), if not set default value of 60 seconds will be used
- KRESMAN_LISTENER: (optional) sets kresman listener for cache, if not set 'http:localhost:8080' is used
- LOCAL_API_PORT: (optional) local api port, if not set default value of 8765 will be used
- KEEP_ALIVE: (optional) specifies the time between keepalive pings, if not set 10s is used
- DISABLE_FILE_LOGS: (optional) disables logging to file, keeps logging to console

Messages:
----------

Message fields are: '**requestId**', '**data**', '**action**'.
Data and action are always present, requestId is present only when the message was initiated by portal, messages initiated by agent don't have them.
. Portal only receives what is in the key '**data**'. Data key needs to be decoded/encoded to BASE64 upon receiving/sending for Wsproxy compatibility,
The **data** key in response is always present and it illustrates how the operation went for the given service/action, _success_ and _failure_ are it's values. 
In case of failure **message** and **body** key are added, message is human readable situation evaluation and body is python error message.

Sample message from agent:

{"requestId": '4as6c4as6d4wf', "action": create,
                    "data": {"status": "failure", "message": "failed to parse/decode request", "body": "some text"}}       


Testing:
----------
Testing is initiated by docker-compose file in tests/integration/ folder. Test result will be display in the logs 
of _current_directory__tester_1 container. Wsproxy is required from Whalebone, the rest can be downloaded/built.


Used volumes:
----------
- /var/run/docker.sock : /var/run/docker.sock - to access docker api
- /etc/whalebone/kres/ : /etc/whalebone/resolver/ - to save resolver config 
- /var/log/whalebone/agent/ : /etc/whalebone/logs/ - to expose its own logs
- /var/sinkhole/ : /etc/whalebone/kresman - sinkhole files for kresman 
- /var/whalebone/cli/ : /etc/whalebone/cli/ - cli agent interface 
- /etc/whalebone/agent/ : /etc/whalebone/compose/ - docker compose and upgrade is exposed
- /var/lib/kres/tty/ : /etc/whalebone/tty/ - tty mapping of resolver processes


Useful Directories:
----------
- /opt/whalebone/ - code is stored here and in certs/ are cert and key files
- /etc/whalebone/compose - resolver docker-compose is here
- /etc/whalebone/logs - agent logs are here
- /etc/whalebone/kres - resolver config si stored here and exposed to the world

