import json
import os
import logging
from datetime import datetime
import shutil
import threading
import time

logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self, config_path, db_path):
        self.config_path = config_path
        self.db_path = db_path
        self.backup_dir = "backups"
        self._backup_thread = None
        self._running = False
        
    def export_config(self, export_path, config_data):
        try:
            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            logger.info(f"Config exported to {export_path}")
            return True
        except Exception as e:
            logger.exception("Failed to export config")
            return False
            
    def import_config(self, import_path):
        try:
            with open(import_path, "r", encoding="utf-8") as f:
                config_data = json.load(f)
            logger.info(f"Config imported from {import_path}")
            return config_data
        except Exception as e:
            logger.exception("Failed to import config")
            return None
            
    def create_backup(self, backup_name=None):
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            if backup_name is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"backup_{timestamp}"
            config_backup_path = os.path.join(self.backup_dir, f"{backup_name}_config.json")
            db_backup_path = os.path.join(self.backup_dir, f"{backup_name}_data.db")
            if os.path.exists(self.config_path):
                shutil.copy2(self.config_path, config_backup_path)
            if os.path.exists(self.db_path):
                shutil.copy2(self.db_path, db_backup_path)
            logger.info(f"Backup created: {backup_name}")
            return True
        except Exception as e:
            logger.exception("Failed to create backup")
            return False
            
    def start_auto_backup(self, interval_hours):
        if self._running:
            return
        self._running = True
        self._backup_thread = threading.Thread(target=self._auto_backup_loop, args=(interval_hours,), daemon=True)
        self._backup_thread.start()
        
    def stop_auto_backup(self):
        self._running = False
        
    def _auto_backup_loop(self, interval_hours):
        while self._running:
            try:
                self.create_backup()
            except Exception as e:
                logger.exception("Auto backup failed")
            time.sleep(interval_hours * 3600)
