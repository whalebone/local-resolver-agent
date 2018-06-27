import asyncio
import ssl
import os
import logging
import websockets

from lr_agent_client import LRAgentClient
from lr_agent_local import LRAgentLocalClient
from exception.exc import InitException
from loggingtools.logger import build_logger


def validate_settings():
    try:
        client_cert = os.environ['LR_CLIENT_CERT']
    except KeyError:
        raise InitException('System env LR_CLIENT_CERT must be set')
    try:
        proxy_address = os.environ['PROXY_ADDRESS']
    except KeyError:
        raise InitException('System env PROXY_ADDRESS must be set')
        # raise InitException('System env WHALEBONE_LR_CLIENT_CERT_PASS must be set')
    if not os.path.exists(client_cert) or os.stat(client_cert).st_size == 0:  # change to None or len()=0
        raise InitException('Client certificate {0} must exist and mustn\'t be empty'.format(client_cert))
    return client_cert, proxy_address


async def connect():
    client_cert, proxy_address = validate_settings()
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(client_cert)
    # sslContext.load_cert_chain(WHALEBONE_LR_CLIENT_CERT)
    logger = logging.getLogger("main")
    logger.info("Connecting to {0}".format(proxy_address))
    return await websockets.connect(proxy_address, ssl=ssl_context)


async def local_resolver_agent_app():
    logger = logging.getLogger("main")
    try:
        interval = int(os.environ['PERIODIC_INTERVAL'])
    except KeyError:
        interval = 60
    while True:
        try:
            websocket = await connect()
            remote_client = LRAgentClient(websocket)
            await remote_client.validate_host()
            asyncio.ensure_future(remote_client.listen())
            # try:
            #     dummy_client = LRAgentClient(None)
            #     local_client = LRAgentLocalClient(dummy_client)
            # except Exception as e:
            #     logger.error("local api runtime error {}".format(e))
            # else:
            #     await local_client.start_api()
            while True:
                await remote_client.send_sys_info()
                await remote_client.validate_host()
                await asyncio.sleep(interval)
        except Exception as e:
            logger.error('Generic error: {}'.format(str(e)))
            logger.error('Retrying in 10 secs...')
            try:
                await websocket.close()
            except Exception:
                pass
            await asyncio.sleep(10)


if __name__ == '__main__':
    if 'LOGGING_LEVEL' in os.environ:
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger("main")
    else:
        logger = build_logger("main", "/etc/whalebone/logs/")
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(local_resolver_agent_app())
        loop.run_forever()
    except InitException as e:
        logger.error(str(e))
    except Exception as e:
        logger.error(str(e))