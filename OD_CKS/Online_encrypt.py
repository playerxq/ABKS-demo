from OD_CKS_DABE import *
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor

def main():
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    GP = dabe.get_global_PP_json("./gpp/global_parameters.json")
    filename = "SERVER_KEY.json"
    pk_ser = {}
    with open(filename, 'r') as f:
        Ser_json = json.load(f)
    for i in (Ser_json['pk_ser']).keys():
        pk_ser['V'] = groupObj.deserialize(bytes(Ser_json['pk_ser']['V'], encoding='utf-8'))
        pk_ser['X'] = groupObj.deserialize(bytes(Ser_json['pk_ser']['X'], encoding='utf-8'))
    with open('./policy.pp', 'r') as f:
        lists = f.readlines()
        policy = lists[0].rstrip('\n')
    with open('./message.pp', 'r') as f:
        pm = f.read()
    # symmetric key for encryption
    ssk = groupObj.random(GT)
    print("\nsymmetric key is\n")
    print(ssk)
    symcrypt = SymmetricCryptoAbstraction(extractor(ssk))
    SSCT = symcrypt.encrypt(pm)
    filename = "SYMMETRIC_CIPHERTEXT.ct"
    with open(filename, 'w') as file_object:
        file_object.write(SSCT)
    #m = groupObj.init(GT, tt)
    # Number of keywords for index generation
    print("\nEncrypted search index is")
    num_kw = int(sys.argv[1])
    keywords = []
    for i in range(0, num_kw):
        keywords.append(sys.argv[2 + i])
    Offline_CT = dabe.get_Offline_CT_json("OFFLINE_CIPHERTEXT.json")
    CT = dabe.online_encrypt(GP, pk_ser, Offline_CT, ssk, policy, keywords)
    print(CT)
    filename = "ENCRYPTED_INDEX.json"
    FullCT_json = {}
    for i in CT.keys():
        if type(CT[i]) == dict:
            FullCT_json[i] = {}
            for j in CT[i].keys():
                FullCT_json[i].update({j: str(groupObj.serialize(CT[i][j]), encoding='utf-8')})
        elif i == 'policy':
            FullCT_json[i] = CT[i]
        else:
            FullCT_json[i] = str(groupObj.serialize(CT[i]), encoding='utf-8')
    with open(filename, 'w') as file_object:
        json.dump(FullCT_json, file_object)


if __name__ == '__main__':
    main()