from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import configparser
import logging

logger = logging.getLogger("veach")


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
            connection_string = f'mongodb+srv://{username}:{password}@{hostname}/{db_name}?retryWrites=true&w=majority'
        else:
            connection_string = f'mongodb+srv://{hostname}/{db_name}?retryWrites=true&w=majority'
    else:
        if username and password:
            connection_string = f'mongodb://{username}:{password}@{hostname}:{port}/{db_name}?retryWrites=true&w=majority'
        else:
            connection_string = f'mongodb://{hostname}:{port}/{db_name}?retryWrites=true&w=majority'
    try:
        client = MongoClient(connection_string)
        logger.info(f'[VEACH DB] Connected to local MongoDB successfully')
    except ConnectionFailure as err:
        logger.error(f'[VEACH DB] Could not connect to MongoDB')

    db_handle = client[db_name]

    return db_handle, client, connection_string


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
        connection_string = f'mongodb://{hostname}:{port}/{db_name}?'
    elif dns_srv_record:
        if username and password:
            connection_string = f'mongodb+srv://{username}:{password}@{hostname}/{db_name}?retryWrites=true&w=majority'
        else:
            connection_string = f'mongodb+srv://{hostname}/{db_name}?retryWrites=true&w=majority'
    else:
        if username and password:
            connection_string = f'mongodb://{username}:{password}@{hostname}:{port}/{db_name}?retryWrites=true&w=majority'
        else:
            connection_string = f'mongodb://{hostname}:{port}/{db_name}?retryWrites=true&w=majority'

    try:
        client = MongoClient(connection_string)
        logger.info(f'[VEACH DB] Connected to remote MongoDB successfully')
    except ConnectionFailure:
        logger.error(f'[VEACH DB] Could not connect to MongoDB')

    db_handle = client[db_name]

    return db_handle, client, connection_string
