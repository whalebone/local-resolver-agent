import asyncio
import ssl
import os
import logging
import websockets

from lr_agent_client import LRAgentClient
# from lr_agent_local import LRAgentLocalClient
from exception.exc import InitException, PongFailedException, TaskFailedException
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
    try:
        connection = await websockets.connect(proxy_address, ssl=ssl_context)
    except Exception as ce:
        raise InitException("Failed to connect to {} due to {}.".format(proxy_address, ce))
    else:
        logger.info("Connected to {}".format(proxy_address))
        return connection


async def task_monitor():
    if "listen" not in [task._coro.__name__ for task in asyncio.all_tasks()]:
        logger = logging.getLogger("main")
        logger.error("Task listen not found in running tasks.")
        raise TaskFailedException


async def main_task_monitor():
    while True:
        if "local_resolver_agent_app" not in [task._coro.__name__ for task in asyncio.all_tasks()]:
            logger = logging.getLogger("main")
            logger.error("Task local_resolver_agent_app not found in running tasks.")
            raise TaskFailedException
        await asyncio.sleep(60)


async def local_resolver_agent_app():
    logger = logging.getLogger("main")
    interval = int(os.environ.get('PERIODIC_INTERVAL', 60))
    task_timeout = int(os.environ.get('TASK_TIMEOUT', 300))
    while True:
        try:
            websocket = await connect()
            remote_client = LRAgentClient(websocket)
            task = asyncio.create_task(remote_client.listen())
            # try:
            #     local_client = LRAgentLocalClient(LRAgentClient(None))
            # except Exception as e:
            #     logger.error("local api runtime error {}".format(e))
            # else:
            #     local_api= await local_client.start_api()
            #     local_task = asyncio.ensure_future(local_api)
            while True:
                for periodic_task in (remote_client.send_sys_info, remote_client.validate_host, task_monitor,
                                      remote_client.create_office365_rpz, remote_client.set_agent_status):
                    await asyncio.wait_for(periodic_task(), task_timeout)
                await asyncio.sleep(interval)
        # except asyncio.exceptions.TimeoutError:
        #     logger.error("Periodic task {} failed to finish in time, Retrying in 10 secs... .".format(periodic_task))
        except Exception as ge:
            try:
                te = task.exception()
                if type(te) in [websockets.exceptions.ConnectionClosed, PongFailedException]:
                    logger.error("Connection error encountered.")
                else:
                    logger.error('Generic error: {}'.format(te))
            except Exception:
                logger.error('Generic error: {}'.format(ge))
        finally:
            try:
                await websocket.close()
                # await local_api.close()
                logger.error('Connection Reset. Retrying in 10 secs...')
            except Exception as ce:
                logger.warning("Failed to cleanup due to {}.".format(ce))
            finally:
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
        loop.create_task(main_task_monitor())
        loop.run_forever()
    except InitException as ie:
        logger.error(str(ie))
    except Exception as e:
        logger.error(str(e))
    finally:
        loop.close()
