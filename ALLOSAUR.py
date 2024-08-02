from random import randint
from functools import reduce
from typing import TypeVar

RETRY_LIMIT = 50

#=======================================================================#
#= Can be swapped out with a type-3 bilinear group and it's operations =#
#=======================================================================#

#============  The type-1 bilinear group (p, Zp, Zp, Zp, *) ============#
# Curve order for BLS12_381
p = 52435875175126190479447740508185965837690552500527637822603658699938581184513
# Typing
class FQ1(int):
    pass
class FQ2(int):
    pass
class FQ12(int):
    pass
# Generators. We're taking G1 = G2 = G12 = Z_p, e(x,y) = (x*y) % p
G1: FQ1 = 1
G2: FQ2 = 1

# realistically I should go through and highlight where we are using group mult vs modular arithmetic, so this is a drag-and-drop for group operations.
def mult(a,b):
    return (a*b) % p
def add(a,b):
    return (a+b) % p
def pairing(a: FQ1,b: FQ2) -> FQ12:
    return (a*b) % p



# Used to sample random elements from G1.
def totally_secure_cryptographic_hash(n: int, seed=612789) -> FQ1:
    g_n = mult(G1, pow(seed + n + 1,-1,p))
    return g_n
# Used to sample random elements from G2.
def totally_secure_cryptographic_hash_2(n: int, seed=612789) -> FQ2:
    g_n = mult(G2, pow(seed + n + 1,-1,p))
    return g_n
# Used to sample random elements from Zp.
def totally_secure_cryptographic_hash_p(n: int, seed=612789) -> FQ2:
    g_n = 19*pow(seed + n + 1,-1,p)
    return g_n

# Realised summing then hashing is probably insecure, so marked it as "totally_secure"
def totally_secure_multi_hash(args: list, /, seed: int = 1231):
    return totally_secure_cryptographic_hash(reduce(add, args), seed=seed) 
# Get many elements, default from G1
def sample_hash(k: int, init: int, _hash = totally_secure_cryptographic_hash, seed=571890) -> list[int]:
    return (_hash(init+i, seed=seed) for i in range(k))


class Params:
    def __init__(self, K: FQ1,K0: FQ1,X: FQ1,Y: FQ1,Z: FQ1,Kt: FQ2):
        self.K: FQ1 = K
        self.K0: FQ1 = K0
        self.X: FQ1 = X
        self.Y: FQ1 = Y
        self.Z: FQ1 = Z
        self.Kt: FQ2 = Kt
class Accumulator:
    def __init__(self, V: FQ1,Qt: FQ2,Qtm: FQ2):
        self.V: FQ1 = V
        self.Qt: FQ2 = Qt
        self.Qtm: FQ2 = Qtm
class Witness:
    def __init__(self, x: int, C: FQ1, Rm: FQ1):
        self.x: int = x
        self.C: FQ1 = C
        self.Rm: FQ1 = Rm

# Generates public parameters and verifies computation.
class TrustedPublicAuthority:
    @staticmethod
    def GGen(salt: int = 121) -> Params:
        # our totally cryptographically secure hash function ===============================================
        pub_g1: list[FQ1] = sample_hash(5, 3281793+salt)
        pub_g2: FQ2 = totally_secure_cryptographic_hash_2(427184961+salt)
        return Params(*pub_g1, pub_g2)

    @staticmethod
    def verify(params: Params, accumulator: Accumulator, y: int, witness: Witness) -> int:
        return all([
            pairing(witness.C, add(mult(y, G2), accumulator.Qt)) == pairing(accumulator.V, G2),
            pairing(witness.Rm, add(mult(y, params.Kt), accumulator.Qtm)) == pairing(add(mult(witness.x,params.K), params.K0), accumulator.Qtm)
        ]) 

class GM:
    def __init__(self, params = TrustedPublicAuthority.GGen()) -> None:
        self.params = params
        self.GKGen()
    
    def GKGen(self) -> None:
        alpha = randint(1,p-1)
        sm = randint(1,p-1)
        v =randint(1,p-1)
        self.secret_key = (alpha, sm)  #====================================================================
        self.accumulator = Accumulator(mult(v, G1), mult(alpha, G2), mult(sm, self.params.Kt))
        self.aux = [set(),{}]
    
    def add(self, y: int) -> None:
        # Accumulate a new value y, and produce it's witness.
        self.aux[0].update({y})
        # C = (y+α)^-1 V
        self.aux[1][y] = self._wit(y)
    
    def revoke(self, y: int) -> None:
        assert(y in self.aux[0])
        self.accumulator.V = self._wit(y)
        self.aux[0] -= {y}
        #intentionall inefficient algorithm as single server context.
        for yp in self.aux[0]:
             self.aux[1][yp] = mult(pow(y-yp,-1,p), add(self.aux[1][yp],mult( -1, self.accumulator.V)))
        
    def issue(self, y: int, h: int, r: int, R: FQ1) -> Witness:
        assert(totally_secure_multi_hash([R, add(mult(r, self.params.K), mult(h,R))], seed=4217890) == h)
        assert(y in self.aux[0])
        Rm = mult(pow(y+self.secret_key[1],-1,p), add(R,self.params.K0))
        C = self.aux[1][y]
        return C, Rm
            
    
    def _wit(self,y, validate=True):
        return mult(pow(y+self.secret_key[0], -1, p),self.accumulator.V)


class User:
    def __init__(self, y, params = TrustedPublicAuthority.GGen()) -> None:
        self.params = params
        self.id = y

    def get_witness(self, y:int, gm: GM):
        if not hasattr(self, "secret_key"):
            self.secret_key = randint(1,p-1)
        k = randint(1,p-1)
        Rid = mult(self.secret_key, self.params.K)
        h = totally_secure_multi_hash([Rid, mult(k, self.params.K)], seed=4217890)
        (C, Rm) = gm.issue(y, h, add(k, mult(-1, mult(h,self.secret_key))), Rid)
        self.witness = Witness(self.secret_key, C, Rm)

    def create_nizk_proof(self, accumulator: Accumulator, challenge: int = 0):
        # Deterministic random values
        r1, r2, r3, *k = sample_hash(11, 4217890, totally_secure_cryptographic_hash_p)
        r = [0,r1,r2,r3]
        # Convenience
        X,Y,Z,K,Kt= self.params.X, self.params.Y, self.params.Z, self.params.K, self.params.Kt
        V,Qt,Qtm = accumulator.V, accumulator.Qt, accumulator.Qtm
        x,C,Rm = self.witness.x, self.witness.C, self.witness.Rm


        # Got bored of writing add, mult. Needs fixing in an ecc context.
        U1 = add(Rm, mult(r1, Z))
        U2 = add(C, mult(r2, Z))
        R = add(add(mult(r1,X),mult(r2,Y)),mult(r3,Z))
        T1 = (k[1]*X+k[2]*Y+k[3]*Z) % p
        T2 = (k[4]*X + k[5] * Y + k[6] * Z - k[7] * R) % p
        Pi1 = (k[0] * pairing(K, Kt) - k[7] * pairing(U1, Kt) + k[4] * pairing(Z, Kt) + k[1] * pairing(Z, Qtm)) % p
        Pi2 = (-k[7] * pairing(U2, G2) + k[5] * pairing(Z, G2) + k[2] * pairing(Z, Qt)) % p
        c = totally_secure_multi_hash([challenge, V, U1, U2, R, T1, T2, Pi1, Pi2])
        s = [k[0] + c * x,
             *[k[i] + c * r[i] for i in range(1,4)],
             *[k[i] + c * r[i-3] * self.id for i in range(4,7)],
             k[7] + c * self.id]
        return U1, U2, R, c, s



class InsecureChannel:
    def __init__(self) -> None:
        self.leaked_data = []

    def user_request_witness(self, user_id, user: User, gm: GM):
        user.get_witness(user_id, gm)
        
        self.leaked_data.append(locals())
    
    def run_proof_check(self, user: User, gm: GM, challenge = 428195):
        proof = user.create_nizk_proof(gm.accumulator, challenge)
        proof_status = self.check_proof(proof, gm.accumulator, gm.params, challenge)

        self.leaked_data.append(locals())
        return proof_status
    
    def check_proof(self, proof, accumulator: Accumulator, params: Params, challenge: int = 0):
        U1, U2, R, c, s = proof
        X,Y,Z,K,Kt,K0 = params.X, params.Y, params.Z, params.K, params.Kt, params.K0
        V,Qt,Qtm = accumulator.V, accumulator.Qt, accumulator.Qtm

        T1 = (s[1] * X + s[2] * Y + s[3] * Z - c * R) % p
        T2 = (s[4] * X + s[5] * Y + s[6] * Z - s[7] * R) % p
        Pi1 = (s[0] * pairing(K,Kt) - s[7] * pairing(U1, Kt) + s[4] * pairing(Z, Kt) + s[1] * pairing(Z, Qtm) + c * pairing(K0, Kt) - c * pairing(U1, Qtm)) % p
        Pi2 =( -s[7]* pairing(U2,G2)+ s[5] * pairing(Z, G2) + s[2] * pairing(Z, Qt) + c * pairing(V, G2) - c * pairing(U2, Qt)) % p
        return all([
            c == totally_secure_multi_hash([challenge, V, U1, U2, R, T1, T2, Pi1, Pi2]),
        ]) 
