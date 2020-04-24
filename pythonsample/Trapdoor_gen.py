from OD_CKS_DABE import *

def main():
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    GP = dabe.get_global_PP_json("./gpp/global_parameters.json")
    TP = {}
    # Number of keywords for seaching
    num_kw = int(sys.argv[1])
    total_kw_num = int(sys.argv[2])
    KW = []
    for i in range(0, num_kw):
        KW.append(sys.argv[3 + i])
    print("\nKeywords for searching %s" % KW)
    K = dabe.get_User_K_json("USER_KEY.json")
    pk_ser = dabe.get_ser_sk_pk_json("SERVER_KEY.json", 0)
    dabe.Trapdoor(GP, pk_ser, K, TP, KW, total_kw_num)
    TP_json = {}
    for i in TP.keys():
        if i == 'z' or i == 'T1' or i == 'T2' or i == 'gid':
            TP_json[i] = str(groupObj.serialize(TP[i]), encoding = 'utf-8')
        elif i == 'T3':
            TP_json['T3'] = {}
            for j in TP['T3'].keys():
                TP_json[i].update({j: str(groupObj.serialize(TP[i][j]), encoding = 'utf-8')})
        elif i != 'num':
            TP_json.update({i: {'tk': str(groupObj.serialize(TP[i]['tk']), encoding='utf-8')}})
        else:
            TP_json['num'] = TP['num']
    filename = "TRAPDOOR.json"
    with open(filename, 'w') as file_object:
        json.dump(TP_json, file_object)
    print(TP)


if __name__ == '__main__':
    main()