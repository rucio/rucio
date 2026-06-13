#!/usr/bin/env python3
"""Set up unique datasets on MOCK RSEs — each statement in its own transaction."""
import uuid
from rucio.core.rse import get_rse_id
from rucio.db.sqla.session import get_engine
from sqlalchemy import text
from datetime import datetime

engine = get_engine()

def run(sql, params=None):
    """Execute SQL in its own transaction. Ignores unique-constraint errors."""
    with engine.connect() as conn:
        with conn.begin():
            try:
                conn.execute(text(sql), params or {})
            except Exception as e:
                if 'duplicate' in str(e).lower() or 'already exists' in str(e).lower():
                    pass  # expected — we're re-running the setup script
                else:
                    raise

mock1 = get_rse_id('MOCK', vo='def')
mock2 = get_rse_id('MOCK2', vo='def')
mock3 = get_rse_id('MOCK3', vo='def')
print(f"MOCK:  {mock1[:8]}...")
print(f"MOCK2: {mock2[:8]}...")
print(f"MOCK3: {mock3[:8]}...")

# Clean old data
run("DELETE FROM dev.load_injection_datasets")
run("DELETE FROM dev.load_injection_plans_history")
run("DELETE FROM dev.load_injection_plans")
run("DELETE FROM dev.dataset_locks")
print("Cleaned old test data")

# Create scope
scope = f"test{uuid.uuid4().hex[:6]}"
run("INSERT INTO dev.scopes (scope, account, is_default, status) "
    "VALUES (:s, 'root', false, 'A') ON CONFLICT DO NOTHING",
    {"s": scope})

now = datetime.utcnow()
datasets = [
    ("ds_10GB",   10_737_418_240, 500, True,  False, False),
    ("ds_100MB",    104_857_600,  50,  True,  False, True),
    ("ds_500MB",    536_870_912,  30,  True,  True,  False),
]

for name, size, length, on_m1, on_m2, on_m3 in datasets:
    run("INSERT INTO dev.dids (scope, name, did_type, account, bytes, length, "
        "availability, is_new, obsolete, hidden, suppressed, purged_replicas, "
        "deleted, created_at, updated_at) VALUES (:s, :n, 'F', 'root', :b, :l, "
        "7, true, false, false, false, false, false, :now, :now) "
        "ON CONFLICT DO NOTHING",
        {"s": scope, "n": name, "b": size, "l": length, "now": now})

    for rse_id, should_lock in [(mock1, on_m1), (mock2, on_m2), (mock3, on_m3)]:
        if should_lock:
            run("INSERT INTO dev.dataset_locks (scope, name, rse_id, state, bytes, length) "
                "VALUES (:s, :n, :r, 'O', :b, :l) "
                "ON CONFLICT DO NOTHING",
                {"s": scope, "n": name, "r": rse_id, "b": size, "l": length})

# Verify
with engine.connect() as conn:
    result = conn.execute(text(
        "SELECT dl.name, r.rse, dl.bytes FROM dev.dataset_locks dl "
        "JOIN dev.rses r ON dl.rse_id = r.id ORDER BY dl.name, r.rse"
    ))
    print(f"\nDatasetLocks:")
    for row in result:
        print(f"  {row.name:12s}  on {row.rse:6s}  {row.bytes/1e9:5.1f} GB")

sep = "=" * 60
print(sep)
print(f"MANUAL TEST READY — {len(datasets)} datasets, scope={scope}")
print(sep)
print()
print("MOCK -> MOCK2:  expect 2 unique (ds_10GB, ds_100MB)")
print("MOCK -> MOCK3:  expect 2 unique (ds_10GB, ds_500MB)")
print("MOCK2 -> MOCK:  expect 0 unique")
print()
print("Run scanner:")
print("  rucio-loadinjector-scanner --run-once --rse-expression 'MOCK'")
print()
print("Check cache:")
print("  docker exec dev-rucio-1 python -c '")
print("from rucio.core.load_injection import get_unique_rse_pair_datasets")
print("from rucio.core.rse import get_rse_id")
print('m1=get_rse_id("MOCK",vo="def")')
print('m2=get_rse_id("MOCK2",vo="def")')
print("ds=get_unique_rse_pair_datasets(m1,m2)")
print('print(f\"MOCK->MOCK2: {len(ds)} unique\")')
print("for d in ds: print(d)")
print("  '")
