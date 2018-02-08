import asyncio
import ssl
import os
import logging
import websockets

from lr_agent_client import LRAgentClient
from exception.exc import InitException
from loggingtools.logger import build_logger

WHALEBONE_LR_CLIENT_CERT = os.environ['WHALEBONE_LR_CLIENT_CERT']
WHALEBONE_PORTAL_ADDRESS = os.environ['WHALEBONE_PORTAL_ADDRESS']



def validate_settings():
    if not WHALEBONE_LR_CLIENT_CERT:
        raise InitException('System env WHALEBONE_LR_CLIENT_CERT must be set')
    if not os.path.exists(WHALEBONE_LR_CLIENT_CERT) or os.stat(WHALEBONE_LR_CLIENT_CERT).st_size == 0:
        raise InitException('Client certificate {0} must exist and mustn\'t be empty'.format(WHALEBONE_LR_CLIENT_CERT))
    if not WHALEBONE_PORTAL_ADDRESS:
        raise InitException('System env WHALEBONE_PORTAL_ADDRESS must be set')


async def connect():
    sslContext = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sslContext.load_cert_chain(WHALEBONE_LR_CLIENT_CERT)
    logger = logging.getLogger(__name__)
    logger.info("Connecting to {0}".format(WHALEBONE_PORTAL_ADDRESS))
    return await websockets.connect(WHALEBONE_PORTAL_ADDRESS, ssl=sslContext)


async def local_resolver_agent_app():
    logger = logging.getLogger(__name__)
    while True:
        try:
            websocket = await connect()
            client = LRAgentClient(websocket)
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
    if os.environ['LOGGING_LEVEL'] == "DEBUG":
        logging.basicConfig(level=logging.DEBUG)
        logger = logging.getLogger(__name__)
    else:
        logger = build_logger(__name__, "/home/narzhan/Downloads/agent_logs/")
    try:
        validate_settings()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(local_resolver_agent_app())
        loop.run_forever()
    except InitException as e:
        logger.error(str(e))
    except Exception as e:
        logger.error(str(e))