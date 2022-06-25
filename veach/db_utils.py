from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import bson
import configparser
import logging
import os

logger = logging.getLogger()

def get_local_db():
    """
    Connects to local MongoDB and returns connection client and specific db handler 
    
    :param None
    :return: db_handler, client
    """
    
    cfg = configparser.ConfigParser()
    cfg.read('config.ini')
    
    hostname = cfg['LOCAL-DATABASE']['hostname']
    port = cfg['LOCAL-DATABASE']['port']
    username = cfg['LOCAL-DATABASE']['username']
    password = cfg['LOCAL-DATABASE']['password']
    db_name = cfg['LOCAL-DATABASE']['db_name']
    dns_srv_record = cfg['LOCAL-DATABASE']['dns_srv_record']
    
    if hostname == "localhost" and not username and not password:
        connection_string = f'mongodb://{hostname}:{port}/'
    elif dns_srv_record:
        if username and password:
            connection_string = f'mongodb+srv://{username}:{password}@{hostname}/?authMechanism=DEFAULT'
        else:
            connection_string = f'mongodb+srv://{hostname}/?authMechanism=DEFAULT'
    else:
        if username and password:
            connection_string = f'mongodb://{username}:{password}@{hostname}:{port}/?authMechanism=DEFAULT'
        else:
            connection_string = f'mongodb://{hostname}:{port}/?authMechanism=DEFAULT'
    try:        
        client = MongoClient(connection_string)
        logger.debug(f'Connected to local MongoDB successfully')
    except ConnectionFailure:
        logger.error(f'Could not connect to MongoDB')
    
    db_handle = client[db_name]
    
    return db_handle, client
        
def get_remote_db():
    """
    Connects to remote MongoDB and returns connection client and specific db handler 
    
    :param None
    :return: db_handler, client
    """
    
    cfg = configparser.ConfigParser()
    cfg.read('config.ini')
    
    hostname = cfg['REMOTE-DATABASE']['hostname']
    port = cfg['REMOTE-DATABASE']['port']
    username = cfg['REMOTE-DATABASE']['username']
    password = cfg['REMOTE-DATABASE']['password']
    db_name = cfg['REMOTE-DATABASE']['db_name']
    dns_srv_record = cfg['REMOTE-DATABASE']['dns_srv_record']
    
    if hostname == "localhost" and not username and not password:
        connection_string = f'mongodb://{hostname}:{port}/'
    elif dns_srv_record:
        if username and password:
            connection_string = f'mongodb+srv://{username}:{password}@{hostname}/?authMechanism=DEFAULT'
        else:
            connection_string = f'mongodb+srv://{hostname}/?authMechanism=DEFAULT'
    else:
        if username and password:
            connection_string = f'mongodb://{username}:{password}@{hostname}:{port}/?authMechanism=DEFAULT'
        else:
            connection_string = f'mongodb://{hostname}:{port}/?authMechanism=DEFAULT'
        
    try:        
        client = MongoClient(connection_string)
        logger.debug(f'Connected to remote MongoDB successfully')
    except ConnectionFailure:
        logger.error(f'Could not connect to MongoDB')
        
    db_handle = client[db_name]
    
    return db_handle, client


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
        db, client = get_remote_db()
        for coll in collections:
            with open(os.path.join(path, f'{coll}.bson'), 'wb+') as f:
                for doc in db[coll].find():
                    f.write(bson.BSON.encode(doc))
    except:
        pass
        


def restore(collections: str, path: str) -> bool:
    """
    MongoDB Restore collections
    
    :param collections: Database collections name
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
