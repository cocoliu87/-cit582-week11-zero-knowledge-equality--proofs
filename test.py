from zksk import Secret, DLRep
from zksk import utils

# Setup: Peggy and Victor agree on two group generators.
# Since Peggy is *committing* rather than encrypted Peggy doesn't know DL_G(H)
G, H = utils.make_generators(num=2, seed=42)

# Setup: generate a secret randomizer for the commitment scheme.
r = Secret(utils.get_random_num(bits=128))

# This is Peggy's secret bit.
top_secret_bit = 1

# A Pedersen commitment to the secret bit.
C = top_secret_bit * G + r.value * H

# Peggy's definition of the proof statement, and proof generation.
# (The first or-clause corresponds to the secret value 0, and the second to the value 1. Because
# the real value of the bit is 1, the clause that corresponds to zero is marked as simulated.)
stmt = DLRep(C, r * H, simulated=True) | DLRep(C - G, r * H)
zk_proof = stmt.prove()
print(zk_proof)
