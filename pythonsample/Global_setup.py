from OD_CKS_DABE import *

def main():
    # arg_len = len(sys.argv)
    # Number of Authorities
    # N = int(sys.argv[1])
    # Total number of the whole keyword set
    # total_kw_num = int(sys.argv[2])
    #N = 3
    #total_kw_num = 20
    # print("\nNumber of Authorities %d" % N)
    # print("\nMax number of keywords %d" % total_kw_num)
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    GP = dabe.setup()
    GP_ser = {}
    for k in GP.keys():
        if k =='g' or k == 'gt':
            GP_ser.update({k: str(groupObj.serialize(GP[k]), encoding = "utf-8")})
    filename = './gpp/global_parameters.json'
    with open(filename, 'w+') as file_object:
        json.dump(GP_ser, file_object)

if __name__ == '__main__':
    main()