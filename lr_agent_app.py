import asyncio
import ssl
import os
import logging
import websockets

from lr_agent_client import LRAgentClient
from exception.exc import InitException
from loggingtools.logger import build_logger


def validate_settings():
    try:
        client_cert = os.environ['WHALEBONE_LR_CLIENT_CERT']
    except KeyError:
        raise InitException('System env WHALEBONE_LR_CLIENT_CERT must be set')
    try:
        proxy_address = os.environ['WHALEBONE_PORTAL_ADDRESS']
    except KeyError:
        raise InitException('System env WHALEBONE_PORTAL_ADDRESS must be set')
    try:
        client_cert_pass = os.environ['WHALEBONE_CLIENT_CERT_PASS']
    except KeyError:
        client_cert_pass = "password" # remove for production
        # raise InitException('System env WHALEBONE_LR_CLIENT_CERT_PASS must be set')

    if not os.path.exists(client_cert) or os.stat(client_cert).st_size == 0:  # change to None or len()=0
        raise InitException('Client certificate {0} must exist and mustn\'t be empty'.format(client_cert))
    return client_cert, proxy_address, client_cert_pass


async def connect():
    client_cert, proxy_address, client_cert_pass = validate_settings()
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(client_cert, password=client_cert_pass)
    # sslContext.load_cert_chain(WHALEBONE_LR_CLIENT_CERT)
    logger = logging.getLogger(__name__)
    logger.info("Connecting to {0}".format(proxy_address))
    return await websockets.connect(proxy_address, ssl=ssl_context)


async def local_resolver_agent_app():
    logger = logging.getLogger(__name__)
    while True:
        try:
            websocket = await connect()
            client = LRAgentClient(websocket)
            await client.validate_host()
            asyncio.ensure_future(client.listen())
            while True:
                await client.send_sys_info()
                await asyncio.sleep(10)
        except Exception as e:
            logger.error('Generic error: {0}'.format(str(e)))
            logger.error('Retrying in 10 secs...')
            try:
                await websocket.close()
            except Exception:
                pass
            await asyncio.sleep(10)


if __name__ == '__main__':
    if 'LOGGING_LEVEL' in os.environ:
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger(__name__)
    else:
        logger = build_logger(__name__, "/tmp/whalebone/logs/")
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(local_resolver_agent_app())
        loop.run_forever()
    except InitException as e:
        logger.error(str(e))
    except Exception as e:
        logger.error(str(e))