from core.db.db_utils import get_local_db
from core.db.sync_collections import dump, restore
from core.models import SyncMeta
from django.core.exceptions import MultipleObjectsReturned
from django.utils import timezone
from enum import Enum
from veach.settings.constants import CVE_DETAILS, CPE_MATCHES, NVD_CVE
import logging

logger = logging.getLogger("veach")


class SyncDb():

    __instance = None
    is_synced = False
    is_syncing = False

    def __init__(self):
        """ Virtually private constructor. """
        if SyncDb.__instance != None:
            raise RuntimeError("This class is a singleton!")
        else:
            SyncDb.__instance = self
            self.client = get_local_db()[1]
            self.state = SyncStates.READY
            self.init_db()

    @classmethod
    def instance(cls):
        if cls.__instance is None:
            logger.debug(f"[SYNC DB] Creating SyncDB singleton")
            SyncDb()
        return SyncDb.__instance
    
    def init_db(self):
        """ 
        A function to initialize the local mongodb database CVE and CPE records.
        The function checks if local cvedetails and cpematches collections exist. If not, it dumps from the remote database and restores locally.
        """

        try:
            db = self.client[NVD_CVE]
            collections = [coll for coll in db.list_collection_names()]
            logger.debug(f'[DB INIT] List of collections in local database: {collections}')
            if CVE_DETAILS and CPE_MATCHES not in collections:
                logger.info(f'[DB INIT] Initializing local mongodb database')
                self.state = SyncStates.STARTED
                SyncDb.is_syncing = True
                dump([CVE_DETAILS, CPE_MATCHES])
                self.state = SyncStates.DUMPED
                restore([CVE_DETAILS])
                self.create_or_update_sync_meta(SyncMeta.CVE)
                restore([CPE_MATCHES])
                self.state = SyncStates.RESTORED
                self.create_or_update_sync_meta(SyncMeta.CPE)
                logger.info(f'[DB INIT] Finished initializing local mongodb database')
                self.state = SyncStates.SYNCED
                SyncDb.is_synced = True
                SyncDb.is_syncing = False
                self.state = SyncStates.SYNCED
            else:
                logger.info(f'[DB INIT] Local mongodb database already initialized')
                self.state = SyncStates.SYNCED
                SyncDb.is_synced = True
        except Exception as err:
            logger.error(
                f'[DB INIT] Could not initialize database | Error: {err}', exc_info=True)

    def create_or_update_sync_meta(self, type: str) -> None:
        type_id = 1 if type == SyncMeta.CVE else 2
        try:
            sync_meta, created = SyncMeta.objects.get_or_create(type=type_id, defaults={'type': 1})
        except MultipleObjectsReturned as err:
            logger.error(f'[GET OR CREATE SYNCMETA] Error: {err}', exc_info=True)

        if not created:
            sync_meta.last_modified_date = timezone.now()
            sync_meta.save()
            logger.info(f'[SYNCMETA UPDATED] Update {type} SyncMeta')
        else:
            logger.info(f'[SYNCMETA CREATED] Created a {type} SyncMeta')


class SyncStates(str, Enum):
    """An enum class for synchronization states"""
    STARTED = "started"
    DUMPED = "dumped"
    RESTORED = "restored"
    SYNCED = "synced"
    READY = "ready"
    
    