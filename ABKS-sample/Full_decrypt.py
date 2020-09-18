from OD_CKS_DABE import *
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor

def main():
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    TP = dabe.get_Trapdoor_json("TRAPDOOR.json")
    par_filelist = get_files("./PARTIAL_CIPHERTEXT")
    if len(par_filelist) == 0:
        return
    des = "./PLAINTEXT/"
    if os.path.exists(des):
        shutil.rmtree(des)
    os.mkdir(des)
    for i in par_filelist:
        Par_CT = dabe.get_Par_CT_json(i)
        orig_m = dabe.full_decrypt(TP, Par_CT)
        #print("\nSymmetric key is")
        #print(orig_m)
        symcrypt = SymmetricCryptoAbstraction(extractor(orig_m))
        filename = "./MATCHED_FILE/SYMMETRIC_CIPHERTEXT_" + (i.split('_'))[3].split('.')[0] + ".ct"
        with open(filename, 'r') as f:
            cm = f.read()
        pm = symcrypt.decrypt(cm)
        #print(str(pm, encoding = 'utf-8'))
        filename = "./PLAINTEXT/SYMMETRIC_PLAINTEXT_" + (i.split('_'))[3].split('.')[0] + ".pp"
        with open(filename, 'w') as file_object:
            file_object.write(str(pm, encoding = 'utf-8'))

if __name__ == '__main__':
    main()