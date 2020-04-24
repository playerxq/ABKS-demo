from OD_CKS_DABE import *
from charm.toolbox.symcrypto import SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor

def main():
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    GP = dabe.get_global_PP_json("./gpp/global_parameters.json")
    filename = "SERVER_KEY.json"
    des = "./CIPHERTEXT/"
    if os.path.exists(des):
        shutil.rmtree(des)
    os.mkdir(des)
    pk_ser = {}
    with open(filename, 'r') as f:
        Ser_json = json.load(f)
    for i in (Ser_json['pk_ser']).keys():
        pk_ser['V'] = groupObj.deserialize(bytes(Ser_json['pk_ser']['V'], encoding='utf-8'))
        pk_ser['X'] = groupObj.deserialize(bytes(Ser_json['pk_ser']['X'], encoding='utf-8'))
    with open('./policy.pp', 'r') as f:
        lists = f.readlines()
        policy = lists[0].rstrip('\n')
    filename_msg = "./MSG/" + sys.argv[1]
    with open(filename_msg, 'r') as f:
        pm = f.read()
    # symmetric key for encryption
    ssk = groupObj.random(GT)
    # print("\nsymmetric key is\n")
    # print(ssk)
    symcrypt = SymmetricCryptoAbstraction(extractor(ssk))
    SSCT = symcrypt.encrypt(pm)
    filename = "./CIPHERTEXT/SYMMETRIC_CIPHERTEXT_" + (((filename_msg.split('/'))[2]).split('.'))[0].upper() + ".ct"
    print("\nGenerated ciphertext is\n")
    print(filename)
    with open(filename, 'w') as file_object:
        file_object.write(SSCT)
    #m = groupObj.init(GT, tt)
    # Number of keywords for index generation
    # print("\nEncrypted search index is")
    num_kw = int(sys.argv[2])
    keywords = []
    for i in range(0, num_kw):
        keywords.append(sys.argv[3 + i])
    Offline_CT = dabe.get_Offline_CT_json("./OFFLINE_CIPHERTEXT/OFFLINE_CIPHERTEXT.json")
    CT = dabe.online_encrypt(GP, pk_ser, Offline_CT, ssk, policy, keywords)
    #print(CT)
    filename = "./CIPHERTEXT/ENCRYPTED_INDEX_" + (((filename_msg.split('/'))[2]).split('.'))[0].upper() + ".json"

    print("\nGenerated encrypted index is\n")
    print(filename)
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