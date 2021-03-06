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
- HTTP_TIMEOUT: (optional) explicit requests timeout (default: 5 seconds)
- CONFIRMATION_REQUIRED: (optional) sets the persistence of upgrade requests
- RPZ_WHITELIST: (optional) enables periodic rpz file creation for domain whitelisting
- RPZ_PERIOD:(optional) the amount of time in seconds between each rpz update (default: 86400 seconds)
- WEBSOCKET_LOGGING: (optional, default: 10) enable logging of Websockets library, should be supplied as integer using Python [logging codes](https://docs.python.org/3/library/logging.html#logging-levels), use levels INFO, DEBUG and ERROR
- TASK_TIMEOUT: (optional) sets timeout for periodic actions in which they have to finish, otherwise error will be thrown
- UPGRADE_SLEEP: (optional, defaul: 0(s)) the number of seconds to sleep between port bind check and old resolver stop in resolver upgrade
- DNS_TIMEOUT: (optional, default: 1(s)) dns resolve timeout parameter
- DNS_LIFETIME: (optional, default 1(s)) dns resolve lifetime parameter
- TRACE_LISTENER: (optional, default: '127.0.0.1:8453') knot http endpoint for domain tracing 
- KRESMAN_PASSWORD: (optional, default: test value) password to use for obtaining Kresman access token 
- KRESMAN_LOGIN: (optional, default: test value) login to use for obtaining Kresman access token


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

Confirmation of actions
----------
The agent's default option is to execute given actions immediately. It is however possible to enable persistence of requests
in order to confirm their execution. This gives the user control over when and what gets executed. To enable the persistence 
of requests set env variable **CONFIRMATION_REQUIRED** to **true**. To list changes the request introduces
the cli option **list** option should be used. To execute the request use cli option **run**. There can only be one persisted request.
If a new request comes while some request is persisted it will be overwritten. To delete waiting request use cli option **delete_request**.
Example:

```
# ./var/whalebone/cli/cli.sh list
-------------------------------
Changes for container
New value for labels container: 1.2
   Old value for labels container: 1.1
------------------------------- 
# ./var/whalebone/cli/cli.sh run
{'container': {'status': 'success'}}
# ./var/whalebone/cli/cli.sh delete_request
Pending configuration request deleted.
```

Testing:
----------
Testing is started by creating containers using **docker-compose.yml** file in tests/integration/ folder. Test result will be display in the logs 
of **tester** container. Testing containers require harbor login to be pulled.


Used volumes:
----------
- /var/run/docker.sock : /var/run/docker.sock - to access docker api
- /etc/whalebone/:/etc/whalebone/etc/
<!-- - /etc/whalebone/kres/ : /etc/whalebone/resolver/ - to save resolver config  -->
- /var/log/whalebone/agent/ : /etc/whalebone/logs/ - to expose its own logs
- /var/sinkhole/ : /etc/whalebone/kresman - sinkhole files for kresman 
- /var/whalebone/cli/ : /etc/whalebone/cli/ - cli agent interface 
<!-- - /etc/whalebone/agent/ : /etc/whalebone/compose/ - docker compose and upgrade is exposed  -->
- /etc/whalebone/:/etc/whalebone/etc/ - suicide folder required for cert deletion 
- /var/whalebone/requests/:/etc/whalebone/requests/ - folder for persisted requests
- /var/lib/kres/tty/ : /etc/whalebone/tty/ - tty mapping of resolver processes


Useful Directories:
----------
- /opt/whalebone/ - code is stored here and in certs/ are cert and key files
- /etc/whalebone/compose - resolver docker-compose is here
- /etc/whalebone/logs - agent logs are here
- /etc/whalebone/kres - resolver config si stored here and exposed to the world

