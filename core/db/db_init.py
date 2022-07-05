from core.db.db_utils import get_local_db
from core.db.sync_collections import dump, restore
from core.models import SyncMeta
from veach.settings.constants import CVE_DETAILS, CPE_MATCHES, NVD_CVE
import logging

logger = logging.getLogger("veach")

def init_db():
    """ 
    A function to initialize the local mongodb database CVE and CPE records.
    The function checks if local cvedetails and cpematches collections exist. If not, it dumps from the remote database and restores locally.
    """

    try:
        client = get_local_db()[1]
        db = client[NVD_CVE]
        collections = [coll for coll in db.list_collection_names()]
        logger.debug(f'[DB INIT] List of collections in local database: {collections}')
        if CVE_DETAILS and CPE_MATCHES not in collections:
            logger.info(f'[DB INIT] Initializing local mongodb database')
            dump([CVE_DETAILS, CPE_MATCHES])
            restore([CVE_DETAILS, CPE_MATCHES])
            logger.info(f'[DB INIT] Finished initializing local mongodb database')

        else:
            logger.info(f'[DB INIT] Local mongodb database already initialized')
    except Exception as err:
        logger.error(
            f'[DB INIT] Could not initialize database | Error: {err}', exc_info=True)


# def create_or_update_sync_meta():
#     SyncMeta.objects.filter()