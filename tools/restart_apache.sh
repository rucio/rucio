source .venv/bin/activate
sudo rm /var/log/apache2/*
sudo rm /tmp/rucio.db /tmp/mock-fts.db
python tools/reset_database.py
sudo /etc/init.d/apache2 restart
sudo chmod 777 /tmp/rucio.db
python tools/sync_meta.py
python tools/sync_rses.py
sudo tail -f /var/log/apache2/*
