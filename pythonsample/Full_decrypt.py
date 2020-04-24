from OD_CKS_DABE import *
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor

def main():
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    TP = dabe.get_Trapdoor_json("TRAPDOOR.json")
    Par_CT = dabe.get_Par_CT_json("PARTIAL_CIPHERTEXT.json")
    orig_m = dabe.full_decrypt(TP, Par_CT)
    print("\nSymmetric key is")
    print(orig_m)
    symcrypt = SymmetricCryptoAbstraction(extractor(orig_m))
    filename = "SYMMETRIC_CIPHERTEXT.ct"
    with open(filename, 'r') as f:
        cm = f.read()
    pm = symcrypt.decrypt(cm)
    #print(str(pm, encoding = 'utf-8'))
    filename = "SYMMETRIC_PLAINTEXT.ct"
    with open(filename, 'w') as file_object:
        file_object.write(str(pm, encoding = 'utf-8'))

if __name__ == '__main__':
    main()