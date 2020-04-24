from OD_CKS_DABE import *


def main():
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)
    GP = dabe.get_global_PP_json("./gpp/global_parameters.json")
    (pk_ser, sk_ser) = dabe.get_ser_sk_pk_json("SERVER_KEY.json", 1)

    filelist = get_files("./CIPHERTEXT")
    matched_file = []
    #print(filelist)
    for i in filelist:
        if (i.split('.'))[2] == "json":
            CT = dabe.get_Full_CT_json(i)
            TP = dabe.get_Trapdoor_json("TRAPDOOR.json")
            global res
            res = dabe.Test(GP, TP, pk_ser, sk_ser, CT)
            if res == 1:
                print("\nConjunctive keyword search successes for file %s" % i)
                matched_file.append(i)
                ct = "./CIPHERTEXT/SYMMETRIC_CIPHERTEXT_" + (i.split('_'))[2].split('.')[0] + ".ct"
                matched_file.append(ct)
    if len(matched_file) == 0:
        print("\nNo file satisfies searching keywords")
    else:
        #print(matched_file)
        des = "./MATCHED_FILE/"
        if os.path.exists(des):
            shutil.rmtree(des)
        os.mkdir(des)

        #os.makedirs(des)
        for sour in matched_file:
            try:
                shutil.copy(sour, des)
            except IOError as e:
                print("Unable to copy file. %s" % e)
            except:
                print("Unexpected error:", sys.exc_info())



if __name__ == '__main__':
    main()