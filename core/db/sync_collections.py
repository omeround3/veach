from pymongo.database import *
from .db_utils import *
import subprocess
import logging

logger = logging.getLogger("veach")


def dump(collections: str, path: str = None) -> bool:
    """
    MongoDB Dump collections dump

    :param collections: Database collections name
    :param path: Path to dump collections
    :return: True is dumped collections successfully, else False

    >>> DB_BACKUP_DIR = '/path/backups/'
    >>> collections = ['collection_name', 'collection_name1', 'collection_name2']
    >>> dump(collections, DB_BACKUP_DIR)

    Example: sync_collections.dump(["cvedetails", "cpematches"])
    Example: sync_collections.dump(["cvedetails", "cpematches"], "/root/veach")
    """

    try:
        db, client, connection_string = get_remote_db()
        logger.info(f'[VEACH DB] Dumping remote collections: {collections}')
        for coll in collections:
            collection = db[coll]
            logger.debug(
                f'[VEACH DB] The collection {coll} has {collection.count_documents({})} documents | dumping collections')
            command = f'mongodump --uri="{connection_string}" --collection={coll}'
            if path:
                command += f' --out={path}'
            logger.debug(f'[VEACH DB] Running command: {command}')
            subprocess.run(["bash", "-c", command],
                           check=True, stdout=subprocess.PIPE)
            logger.debug(f'[VEACH DB] Dumped collection {coll}')
        logger.info(
            f'[VEACH DB] Finished dumping mongo db collections: {collections}')
        return True
    except FileNotFoundError as err:
        logger.error(
            f'[VEACH DB] Process failed because the executable could not be found. \n{err}', exc_info=True)
    except subprocess.CalledProcessError as exc:
        logger.error(
            f"[VEACH DB] Process failed because did not return a successful return code. "
            f"Returned {exc.returncode}\n{exc}",
            exc_info=True
        )
    except subprocess.TimeoutExpired as exc:
        logger.error(f"[VEACH DB] Process timed out.\n{exc}")
    except Exception as err:
        logger.error(
            f'[VEACH DB] Could not dump remote collections: {collections} | Error: {err}', exc_info=True)
    return False


def restore(collections: str, path: str = "dump/") -> bool:
    """
    MongoDB Restore collections

    :param path: Database dumped path
    :return: True is restored collections successfully, else False

    >>> DB_BACKUP_DIR = '/path/backups/'
    >>> conn = MongoClient("mongodb://admin:admin@127.0.0.1:27017", authSource="admin")
    >>> db_name = 'my_db'
    >>> restore(DB_BACKUP_DIR, conn, db_name)

    Example: sync_collections.restore(["cvedetails", "cpematches"])
    Example: sync_collections.restore(["cvedetails", "cpematches"], "dump/")
    """

    try:
        db, client, connection_string = get_local_db()
        logger.info(f'[VEACH DB] Restoring remote collections: {collections}')
        for coll in collections:
            logger.debug(
                f'[VEACH DB] Restoring the collection {coll} ')
            command = f'mongorestore --uri="{connection_string}" --drop --nsInclude=nvdcve.{coll} {path}'
            logger.debug(f'[VEACH DB] Running command: {command}')
            subprocess.run(["bash", "-c", command],
                           check=True, stdout=subprocess.PIPE)
            logger.debug(f'[VEACH DB] Restored collection {coll}')
        logger.info(
            f'[VEACH DB] Finished restoring mongo db collections: {collections}')
        return True
    except FileNotFoundError as err:
        logger.error(
            f'[VEACH DB] Process failed because the executable could not be found. \n{err}', exc_info=True)
    except subprocess.CalledProcessError as exc:
        logger.error(
            f"[VEACH DB] Process failed because did not return a successful return code. "
            f"Returned {exc.returncode}\n{exc}",
            exc_info=True
        )
    except subprocess.TimeoutExpired as exc:
        logger.error(f"[VEACH DB] Process timed out.\n{exc}", exc_info=True)
    except Exception as err:
        logger.error(
            f'[VEACH DB] Could not restore collections: {collections} | Error: {err}', exc_info=True)
    return False
