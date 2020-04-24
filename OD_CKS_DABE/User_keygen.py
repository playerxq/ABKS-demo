from OD_CKS_DABE import *

def main():
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    GP = dabe.get_global_PP_json("./gpp/global_parameters.json")

    gid = sys.argv[1]
    print("\nGenerate attribute secret keys of user %s" % gid)
    fname = sys.argv[2]
    user_attr_set = []
    with open(fname, 'r') as fa:
        lists = fa.readlines()
    for i in range(0, len(lists)):
        user_attr_set.append(lists[i].rstrip('\n'))
    print("\nUser's attribute set is %s" % user_attr_set)
    N = int(sys.argv[3])
    K = {}
    print("\nUser's attributes come from %d authorities" % N)
    for i in range(1, N + 1):
        auth_fname = 'auth_attr_set' + str(i) + '.pp'
        with open(auth_fname, 'r') as fa:
            lists = fa.readlines()
        auth_set = []
        for j in range(0, len(lists)):
            auth_set.append(lists[j].rstrip('\n'))
        intersection = list(set(auth_set).intersection(set(user_attr_set)))
        if len(intersection):
            auth_key_name = 'auth_attr_key'.upper() + str(i) + '.json'
            with open(auth_key_name, 'r') as f:
                SK_json = json.load(f)
            SK = {}
            for i in (SK_json['sk']).keys():
                SK.update({i: {'alpha_i': groupObj.deserialize(bytes(SK_json['sk'][i]['alpha_i'], encoding = 'utf-8')), 'y_i': groupObj.deserialize(bytes(SK_json['sk'][i]['y_i'], encoding = 'utf-8'))}})
            for j in intersection:
                dabe.keygen(GP, SK, j, gid, K)
    filename = "USER_KEY.json"
    K_json = {}
    for i in K.keys():
        if i == 'gid':
            K_json.update({'gid':gid})
        else:
            K_json.update({i: {'k': str(groupObj.serialize(K[i]['k']), encoding = 'utf-8')}})
    with open(filename, 'a') as file_object:
        json.dump(K_json, file_object)


if __name__ == '__main__':
    main()