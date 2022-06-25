from bson.json_util import dumps
from pymongo.database import *
from os.path import join
from .db_utils import *
from ..utils import timeit
import bson
import subprocess


@timeit
def dump(collections: str, path: str) -> bool:
    """
    MongoDB Dump collections dump

    :param collections: Database collections name
    :param path: Path to dump collections
    :return: True is dumped collections successfully, else False

    >>> DB_BACKUP_DIR = '/path/backups/'
    >>> collections = ['collection_name', 'collection_name1', 'collection_name2']
    >>> dump(collections, DB_BACKUP_DIR)
    """

    try:
        db, client, connection_string = get_remote_db()
        print(f'[VEACH DB] Dumping remote collections: {collections}')
        for coll in collections:
            collection = db[coll]
            print(
                f'[VEACH DB] The collection {coll} has {collection.count_documents({})} documents | dumping collections')
            command = f'mongodump --uri="{connection_string}" --collection={coll}'
            print(f'[VEACH DB] Running command: {command}')
            subprocess.run(["bash", "-c", command],
                           check=True, stdout=subprocess.PIPE)
            print(f'[VEACH DB] Dumped collection {coll}')
        print(
            f'[VEACH DB] Finished dumping mongo db collections: {collections}')
    except FileNotFoundError as err:
        print(
            f'[VEACH DB] Process failed because the executable could not be found. \n{err}')
    except subprocess.CalledProcessError as exc:
        print(
            f"[VEACH DB] Process failed because did not return a successful return code. "
            f"Returned {exc.returncode}\n{exc}"
        )
    except subprocess.TimeoutExpired as exc:
        print(f"[VEACH DB] Process timed out.\n{exc}")
    except:
        logger.error(
            f'[VEACH DB] Could not dump remote collections: {collections}')


def restore(collections: str, path: str) -> bool:
    """
    MongoDB Restore collections

    :param path: Database dumped path
    :return: True is restored collections successfully, else False

    >>> DB_BACKUP_DIR = '/path/backups/'
    >>> conn = MongoClient("mongodb://admin:admin@127.0.0.1:27017", authSource="admin")
    >>> db_name = 'my_db'
    >>> restore(DB_BACKUP_DIR, conn, db_name)

    """

    try:
        db, client, connection_string = get_local_db()
        print(f'[VEACH DB] Restoring remote collections: {collections}')
        for coll in collections:
            collection = db[coll]
            print(
                f'[VEACH DB] The collection {coll} has {collection.count_documents({})} documents | restoring collections')
            command = f'mongorestore --uri="{connection_string}" --nsInclude=nvdcve.{coll} dump/'
            print(f'[VEACH DB] Running command: {command}')
            subprocess.run(["bash", "-c", command],
                            check=True, stdout=subprocess.PIPE)
            print(f'[VEACH DB] Restored collection {coll}')
        print(
            f'[VEACH DB] Finished restoring mongo db collections: {collections}')
    except FileNotFoundError as err:
        print(
            f'[VEACH DB] Process failed because the executable could not be found. \n{err}')
    except subprocess.CalledProcessError as exc:
        print(
            f"[VEACH DB] Process failed because did not return a successful return code. "
            f"Returned {exc.returncode}\n{exc}"
        )
    except subprocess.TimeoutExpired as exc:
        print(f"[VEACH DB] Process timed out.\n{exc}")
    except:
        logger.error(
            f'[VEACH DB] Could not restore collections: {collections}')
