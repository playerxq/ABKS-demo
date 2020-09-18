from OD_CKS_DABE import *

def main():
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    GP = dabe.get_global_PP_json("./gpp/global_parameters.json")

    (sk_ser, pk_ser) = dabe.ser_setup(GP)
    Server_keys = {}
    Server_keys['sk_ser'] = {'v': str(groupObj.serialize(sk_ser['v']), encoding = "utf-8"), 'x': str(groupObj.serialize(sk_ser['x']), encoding = "utf-8")}
    Server_keys['pk_ser'] = {'V': str(groupObj.serialize(pk_ser['V']), encoding = "utf-8"), 'X': str(groupObj.serialize(pk_ser['X']), encoding = "utf-8")}
    filename = 'SERVER_KEY.json'
    with open(filename, 'w+') as file_object:
        json.dump(Server_keys, file_object)

if __name__ == '__main__':
    main()