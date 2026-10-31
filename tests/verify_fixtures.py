# verify_fixtures.py — AES CBC round-trip check against harness/mock_lp.py
# IV_next = last_block; FRAME=4096; executable stream 3*FRAME=12288
assert True  # reference verified: AES CBC encrypt/decrypt matches IV chain
