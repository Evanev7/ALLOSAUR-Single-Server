from random import randint
num_attempts = 100
num_users = 200

from ALLOSAUR import *


def test_witness_issuing(num_attempts, num_users):

    num_correct_registrations = 0
    num_correct_witness_nonissues = 0
    num_correct_revocations = 0
    num_validated_proofs = 0
    num_correctly_invalidated_proofs = 0 
    num_incorrectly_invalidated_proofs = 0
    num_incorrect_registrations = 0


    for _ in range(num_attempts):
        params = TrustedPublicAuthority.GGen(randint(0, 14289017))
        gm = GM(params=params)
        channel = InsecureChannel()
        users = [User(randint(0,51289571),params=params) for _ in range(num_users)]

        for user in users:
            gm.add(user.id)
            
            channel.user_request_witness(user.id, user, gm)
            if TrustedPublicAuthority.verify(params, gm.accumulator, user.id, user.witness):
                num_correct_registrations += 1
            else:
                num_incorrect_registrations += 1
            try:
                channel.user_request_witness(randint(0,51289571), user, gm)
            except AssertionError:
                num_correct_witness_nonissues += 1

        for user in users:
            
            if is_revoked := randint(1,3) < 2:
                gm.revoke(user.id)
            try:
                channel.user_request_witness(user.id, user, gm)
                assert(not is_revoked)
            except AssertionError:
                assert(is_revoked)
                num_correct_revocations += 1
            
            if channel.run_proof_check(user, gm, randint(0,3215170)):
                num_validated_proofs += 1
            else:
                if is_revoked:
                    num_correctly_invalidated_proofs += 1
                else:
                    num_incorrectly_invalidated_proofs += 1
    
        
    print(f"""      {num_attempts} test runs over {num_users} users
        {num_correct_registrations} correctly verified
        {num_incorrect_registrations} incorrectly verified
        {num_correct_witness_nonissues} correctly dismissed
        {num_correct_revocations} correctly revoked
        {num_validated_proofs} proofs checked
        {num_correctly_invalidated_proofs} invalid proofs failed checks
        {num_incorrectly_invalidated_proofs} valid proofs failed checks """)

    return channel





















if __name__ == "__main__":
    test_witness_issuing(num_attempts=num_attempts, num_users=num_users)