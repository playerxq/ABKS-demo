from OD_CKS_DABE import *

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
    with open('./attribute_set.pp', 'r') as fa:
        lists = fa.readlines()
    attrs_set = []
    for i in range(0, len(lists)):
        attrs_set.append(lists[i].rstrip('\n'))
    N = int(sys.argv[1])
    #N = 1
    print("\nNumber of authorities is %d" % N)
    total_kw_num = int(sys.argv[2])
    #total_kw_num = 20
    print("\nTotal number of keywords used to generate offline ciphertext is %d" % total_kw_num)
    PK = {}
    for i in range(1, N + 1):
        auth_key_name = 'auth_attr_key'.upper() + str(i) + '.json'
        with open(auth_key_name, 'r') as f:
            PK_json = json.load(f)
            for i in (PK_json['pk']).keys():
                PK.update({i: {'e(gg)^alpha_i': groupObj.deserialize(bytes(PK_json['pk'][i]['e(gg)^alpha_i'], encoding = 'utf-8')), 'g^y_i': groupObj.deserialize(bytes(PK_json['pk'][i]['g^y_i'], encoding = 'utf-8'))}})
    offline_CT = dabe.offline_encrypt(GP, PK, pk_ser, attrs_set, total_kw_num)
    filename = "./OFFLINE_CIPHERTEXT/OFFLINE_CIPHERTEXT.json"
    OffCT_json = {}
    des = "./OFFLINE_CIPHERTEXT/"
    if os.path.exists(des):
        shutil.rmtree(des)
    os.mkdir(des)
    for i in offline_CT.keys():
        if type(offline_CT[i]) == dict:
            OffCT_json[i] = {}
            for j in offline_CT[i].keys():
                OffCT_json[i].update({j: str(groupObj.serialize(offline_CT[i][j]), encoding = 'utf-8')})
        else:
            OffCT_json[i] = str(groupObj.serialize(offline_CT[i]), encoding='utf-8')
    with open(filename, 'w') as file_object:
        json.dump(OffCT_json, file_object)
    print(offline_CT)

if __name__ == '__main__':
    main()