from OD_CKS_DABE import *

def main():
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    GP = dabe.get_global_PP_json("./gpp/global_parameters.json")
    auth_attr_set = []
    fname = sys.argv[1]
    with open(fname, 'r') as fa:
        lists = fa.readlines()
    for i in range(0, len(lists)):
        auth_attr_set.append(lists[i].rstrip('\n'))
    (SK, PK) = dabe.authsetup(GP,auth_attr_set)
    Auth_attr_keys_sk = {}
    Auth_attr_keys_pk = {}
    for i in auth_attr_set:
        Auth_attr_keys_sk.update({i.upper(): {'alpha_i': str(groupObj.serialize(SK[i.upper()]['alpha_i']), encoding="utf-8"),
                             'y_i': str(groupObj.serialize(SK[i.upper()]['y_i']), encoding="utf-8")}})
        Auth_attr_keys_pk.update({i.upper(): {'e(gg)^alpha_i': str(groupObj.serialize(PK[i.upper()]['e(gg)^alpha_i']), encoding="utf-8"),
                             'g^y_i': str(groupObj.serialize(PK[i.upper()]['g^y_i']), encoding="utf-8")}})

    filename = fname.replace(fname[10:13], "key")
    filename = ((filename.split('.'))[0]).upper() + '.json'
    Auth_attr_keys = {}
    Auth_attr_keys['sk'] = Auth_attr_keys_sk
    Auth_attr_keys['pk'] = Auth_attr_keys_pk
    with open(filename, 'w+') as file_object:
        json.dump(Auth_attr_keys, file_object)

if __name__ == '__main__':
    main()





