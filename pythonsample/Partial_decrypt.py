from OD_CKS_DABE import *

def main():
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    GP = dabe.get_global_PP_json("./gpp/global_parameters.json")
    TP = dabe.get_Trapdoor_json("TRAPDOOR.json")
    CT = dabe.get_Full_CT_json("ENCRYPTED_INDEX.json")
    partial_ct = dabe.partial_decrypt(GP, TP, CT)
    print("\nPartial decryption: %s" % partial_ct)
    filename = "PARTIAL_CIPHERTEXT.json"
    ParCT_json = {}
    for i in partial_ct.keys():
        ParCT_json[i] = str(groupObj.serialize(partial_ct[i]), encoding='utf-8')
    with open(filename, 'w') as file_object:
        json.dump(ParCT_json, file_object)

if __name__ == '__main__':
    main()