from bson.json_util import dumps
from pymongo.database import *
from os.path import join
from .db_utils import *
from ..utils import timeit
import json
import bson
import subprocess


@timeit
def dump(collections: str, path: str) -> bool:
    """
    MongoDB Dump collections dump

    :param collections: Database collections name
    :param path: Path to dump collections
    :return:

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
                f'[VEACH DB] The collection {coll} has {collection.count_documents({})}')
            
            # client.admin.command(f"mongodump --db={db.name} --collection={coll} --out={path}")
            print(f'[VEACH DB] Running command: mongodump --uri={connection_string} --db={db.name} --collection={coll} --out={path}')
            command = f"mongodump --uri={connection_string} --collection={coll} --out={path}"
            subprocess.run(command, check=True, capture_output=True)
            # with open(join(path, f'{coll}.json'), 'w+') as file:
            #     for doc in db[coll].find():
            #         json.dump(json.loads(dumps(doc)), file)
            print(f'[VEACH DB] Dumped collection {coll}')
        print(
            f'[VEACH DB] Finished dumping mongo db collections: {collections}')
    except:
        logger.error(
            f'[VEACH DB] Could not dump remote collections: {collections}')


def restore(path: str) -> bool:
    """
    MongoDB Restore collections

    :param path: Database dumped path
    :return:

    >>> DB_BACKUP_DIR = '/path/backups/'
    >>> conn = MongoClient("mongodb://admin:admin@127.0.0.1:27017", authSource="admin")
    >>> db_name = 'my_db'
    >>> restore(DB_BACKUP_DIR, conn, db_name)

    """

    db, client = get_local_db()
    for coll in os.listdir(path):
        if coll.endswith('.bson'):
            with open(os.path.join(path, coll), 'rb+') as f:
                db[coll.split('.')[0]].insert_many(bson.decode_all(f.read()))
