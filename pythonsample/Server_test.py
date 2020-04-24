from OD_CKS_DABE import *

def main():
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    GP = dabe.get_global_PP_json("./gpp/global_parameters.json")
    (pk_ser, sk_ser) = dabe.get_ser_sk_pk_json("SERVER_KEY.json", 1)
    CT = dabe.get_Full_CT_json("ENCRYPTED_INDEX.json")
    TP = dabe.get_Trapdoor_json("TRAPDOOR.json")
    res = dabe.Test(GP, TP, pk_ser, sk_ser, CT)
    if res == 1:
        print("\nConjunctive search successes")
    else:
        print("\nConjunctive search fails")

if __name__ == '__main__':
    main()