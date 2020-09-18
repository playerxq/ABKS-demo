# Efficient decentralized attribute-based approach with online/offline encryption and outsourced decryption
# Enhanced with conjunctive keyword search
# Author Xu Qian
# Data 2020-4-17
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import sys
import json
import numpy as np

debug = False


class Dabe(ABEncMultiAuth):

    def __init__(self, groupObj):
        ABEncMultiAuth.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)  # Create Secret Sharing Scheme
        group = groupObj  #:Prime order group

    def get_global_PP_json(self, filename):
        with open(filename, 'r') as f:
            GP_ser = json.load(f)
        GP = {}
        for i in GP_ser.keys():
            if i == 'g':
                GP.update({'g': bytes(GP_ser[i], encoding="utf-8")})
            else:
                GP.update({'gt': bytes(GP_ser[i], encoding="utf-8")})
        for k in GP.keys():
            GP[k] = group.deserialize(GP[k])
        H = lambda str: GP['g'] ** group.hash(str)
        # Hash used for keyword search
        H2 = lambda str: group.hash(str)
        GP['H'] = H
        GP['H2'] = H2
        return GP

    def setup(self):
        '''Global Setup'''
        #:In global setup, a bilinear group G of prime order p is chosen
        #:The global public parameters, GP and p, and a generator g of G. A random oracle H maps global identities GID to elements of G
        g = group.random(G1)
        gt = group.random(G1)
        #: The oracle that maps global identities GID onto elements of G
        H = lambda str: g**group.hash(str)
        # Hash used for keyword search
        H2 = lambda str: group.hash(str)
        #H = lambda x: group.hash(x, G1)
        GP = {'g': g, 'gt': gt, 'H': H, 'H2':H2}
        return GP

    def encode(self, str):

        pass

    def decode(self, element_t):
        if type(element_t) != type(group.random(GT)):
            print("\nType of plaintext is invalid")
            return
        else:
            pass

    # Run by each authority
    def authsetup(self, GP, attributes):
        '''Authority Setup for a given set of attributes'''
        # PK={e(g,g)^alpha_i, g^y_i} for each attribute
        # SK = {alpha_i, y_i} as its secret key
        SK = {}
        PK = {}
        for i in attributes:
            alpha_i, y_i = group.random(), group.random()
            e_gg_alpha_i = pair(GP['g'], GP['g']) ** alpha_i
            g_y_i = GP['g'] ** y_i
            SK[i.upper()] = {'alpha_i': alpha_i, 'y_i': y_i}
            PK[i.upper()] = {'e(gg)^alpha_i': e_gg_alpha_i, 'g^y_i': g_y_i}

        if (debug):
            print("Authority Setup for %s" % attributes)
            print("SK = {alpha_i, y_i}")
            print(SK)
            print("PK = {e(g,g) ^ alpha_i, g ^ y_i}")
            print(PK)

        return (SK, PK)

    def get_ser_sk_pk_json(self, filename, flag):
        pk_ser, sk_ser = {}, {}
        with open(filename, 'r') as f:
            Ser_json = json.load(f)
        for i in (Ser_json['pk_ser']).keys():
            pk_ser['V'] = group.deserialize(bytes(Ser_json['pk_ser']['V'], encoding='utf-8'))
            pk_ser['X'] = group.deserialize(bytes(Ser_json['pk_ser']['X'], encoding='utf-8'))
        for i in (Ser_json['sk_ser']).keys():
            sk_ser['v'] = group.deserialize(bytes(Ser_json['sk_ser']['v'], encoding='utf-8'))
            sk_ser['x'] = group.deserialize(bytes(Ser_json['sk_ser']['x'], encoding='utf-8'))
        if flag:
            return (pk_ser, sk_ser)
        else:
            return pk_ser

    def ser_setup(self, gp):
        v = group.random()
        x = group.random()
        SK, PK = {}, {}
        SK['v'] = v
        SK['x'] = x
        PK['V'] = gp['g'] ** v
        PK['X'] = gp['gt'] ** x
        return (SK,PK)

    def right_shift(self, coeff, deg):
        '''right shift coeff from deg to deg + 1'''
        for i in range(deg + 1, 0, -1):
            coeff[i] = coeff[i - 1]
        coeff[0] = 0

    def step_add(self, coeff, deg, a):
        self.right_shift(coeff, deg)
        for i in range(0, deg + 1):
            coeff[i] += ((-1) * a * coeff[i + 1])

    def intofcoefcal(self, root_list):
        '''get integer for polynomial calculation'''
        l = len(root_list)
        mmcoeff = [0] * (l + 1)
        mmcoeff[0] = -1 * root_list[0]
        mmcoeff[1] = 1
        deg = 1
        for i in range(1, l):
            self.step_add(mmcoeff, deg, root_list[i])
            deg += 1
        return mmcoeff

    def getcoefroot(self, gp, root_list):
        '''calculate coeffs of polynomial rooted at root_list'''
        coe = {}
        mmcoeff = self.intofcoefcal(root_list)
        for i in range(0, len(mmcoeff)):
            coe.update({str(i): mmcoeff[i]})
        return coe

    def evap(self, coeffs, root_list):
        '''evaluate polynomial for debug'''
        l = len(root_list)
        col = len(coeffs)
        if l != col - 1:
            return -1
        sum_r = 0
        for i in root_list:
            summ = 0
            for j in range(l, -1, -1):
                summ *= i
                summ += coeffs[str(j)]
            sum_r += summ
        return sum_r

    def get_User_K_json(self, filename):
        K = {}
        with open(filename, 'r') as f:
            K_json = json.load(f)
        for i in K_json.keys():
            if i == 'gid':
                K['gid'] = K_json['gid']
            else:
                K.update({i: {'k': group.deserialize(bytes(K_json[i]['k'], encoding='utf-8'))}})
        return K

    #Run by each authority
    def keygen(self, gp, sk, i, gid, skey):
        '''Create a key for GID on attribute i belonging to authority sk
        sk: attribute secret key of authority
        i: attribute owned by user gid and meanwhile monitored by authority
        skey: attribute secret key of user gid computed by authority whose attribute set containing the user's attribute
        '''
        # For each attribute i, authority computes K_{i,GID} = g^alpha_i * H(GID)^y_i for user gid
        h = gp['H'](gid)
        K = (gp['g'] ** sk[i.upper()]['alpha_i']) * (h ** sk[i.upper()]['y_i'])

        skey[i.upper()] = {'k': K}
        skey['gid'] = gid

        if (debug):
            print("\nKey gen for %s on %s" % (gid, i))
            print("\nH(GID): '%s'" % h)
            print("\nK = g^alpha_i * H(GID) ^ y_i: %s" % K)
        return None

    def get_Trapdoor_json(self, filename):
        with open(filename, 'r') as f:
            TP_json = json.load(f)
        TP = {}
        for i in TP_json.keys():
            if i == 'z' or i == 'T1' or i == 'T2' or i == 'gid':
                TP[i] = group.deserialize(bytes(TP_json[i], encoding='utf-8'))
            elif i == 'T3':
                TP[i] = {}
                for j in TP_json['T3'].keys():
                    TP[i].update({j: group.deserialize(bytes(TP_json[i][j], encoding='utf-8'))})
            elif i != 'num':
                TP.update({i: {'tk': group.deserialize(bytes(TP_json[i]['tk'], encoding='utf-8'))}})
            else:
                TP['num'] = TP_json['num']
        return TP

    # Trapdoor
    def Trapdoor(self, gp, pk_ser, skey, tp, KW, key_nums):
        '''Transform user's attribute secret key for outsourced decryption and search. Run on the user side'''
        # key_nums: total number of the keywords, may degrade the security and scalability
        z = group.random()
        z_inv = z ** -1
        T_1 = group.random()
        e = group.random()
        T_2 = gp['gt'] ** e
        tp['z'] = z
        tp['gid'] = gp['H'](skey['gid']) ** z_inv
        tp['T1'] = T_1
        tp['T2'] = T_2
        T_3 = {}
        for key, value in skey.items():
            if key == 'gid':
                continue
            tp[key] = {'tk': value['k'] ** z_inv}
            if (debug):
                print("\nTP for attr %s = %s" % (key,tp[key]['tk']))
        t = len(KW)
        m = group.init(ZR, t)
        for i in range(0,key_nums+1):
            sum_i = 0
            for k in KW:
                sum_i += (gp['H2'](k) ** i)
            num = (gp['gt'] ** ((m ** -1) * T_1 * sum_i))
            T_3[str(i)] = (num * (pk_ser['X'] ** e))
        tp['T3'] = T_3
        tp['num'] = t
        return None

    def get_Par_CT_json(self,filename):
        Par_CT = {}
        with open(filename, 'r') as f:
            ParCT_json = json.load(f)
        for i in ParCT_json.keys():
            Par_CT[i] = group.deserialize(bytes(ParCT_json[i], encoding='utf-8'))
        return Par_CT

    def get_Offline_CT_json(self, filename):
        with open(filename, 'r') as f:
            OffCT_json = json.load(f)
        Offline_CT = {}
        for i in OffCT_json.keys():
            if type(OffCT_json[i]) == dict:
                Offline_CT[i] = {}
                for j in OffCT_json[i].keys():
                    Offline_CT[i].update({j: group.deserialize(bytes(OffCT_json[i][j], encoding='utf-8'))})
            else:
                Offline_CT[i] = group.deserialize(bytes(OffCT_json[i], encoding='utf-8'))
        return Offline_CT

    def offline_encrypt(self, gp, pk, pk_ser, attributes, key_num):
        '''Performed on the data owner side'''
        # attributes: the attribute set required to generate the attribute policy. attributes will lead to the leakage of user's privacy in some cases and limit the scalability
        # pk: public keys of the authorities
        # pk_ser: public key of the server
        # key_num: Total number of keywords
        egg = pair(gp['g'], gp['g'])
        theta = group.random()
        u = group.random()
        s2 = group.random()
        C1, C2, C3, C4 = {}, {}, {}, {}
        CS1, CS2 = {}, {}
        C_lambda, C_delta, C_u = {}, {}, {}
        W, W_i = {}, {}
        if debug: C_alpha, C_r = {}, {}
        for i in attributes:
            lambda_i = group.random()
            alpha_i = group.random()
            y_i = group.random()
            delta_i = group.random()
            r_i = group.random()
            u_i = group.random()
            C_lambda[i.upper()] = lambda_i
            C_delta[i.upper()] = delta_i
            C_u[i.upper()] = u_i
            C1[i.upper()] = (egg ** lambda_i) * (egg ** (alpha_i * r_i))
            C2[i.upper()] = gp['g'] ** r_i
            C3[i.upper()] = (gp['g'] ** (y_i * r_i)) * (gp['g'] ** delta_i)
            C4[i.upper()] = gp['g'] ** (theta * u_i)
            CS1[i.upper()] =  (pk[i.upper()]['e(gg)^alpha_i'] ** r_i) * (egg ** (-1 * (alpha_i * r_i)))
            CS2[i.upper()] = (pk[i.upper()]['g^y_i'] ** r_i) * gp['g'] ** (-1 * (y_i * r_i))
        CX1 = (pair(pk_ser['X'], pk_ser['V']) ** (theta * u)) * (pair(gp['g'],gp['gt']) ** (-1 * s2))
        for i in range(0, key_num+1):
            n_i = group.random()
            W_i[str(i)] = n_i
            W[str(i)] = gp['g'] ** (n_i * (s2 ** (i + 1)))
        #print(type(CX1))
        #print(type(C1))
        #print(type(C_lambda))
        return {'CX1': CX1, 'C1':C1, 'C2':C2, 'C3':C3, 'C4':C4, 'CS1':CS1, 'CS2':CS2, 'lambda':C_lambda, 'delta':C_delta, 'u':C_u, 'W_I':W, 'n':W_i, 'theta':theta, 'miu':u, 's2':s2}

    def get_Full_CT_json(self, filename):
        with open(filename, 'r') as f:
            CT_json = json.load(f)
        CT = {}
        for i in CT_json.keys():
            if type(CT_json[i]) == dict:
                CT[i] = {}
                for j in CT_json[i].keys():
                    CT[i].update({j: group.deserialize(bytes(CT_json[i][j], encoding='utf-8'))})
            elif i == 'policy':
                CT[i] = CT_json[i]
            else:
                CT[i] = group.deserialize(bytes(CT_json[i], encoding='utf-8'))
        return CT


    def online_encrypt(self, gp, pk_ser, ct, M, policy_str, keywords):
        '''online encryption performed on the user side'''
        s1 = group.random()
        u = group.random()
        e = group.init(ZR, 1)
        egg_s = pair(gp['g'], gp['g']) ** s1
        C0 = M * egg_s
        C5, C6, C7 = {}, {}, {}
        policy = util.createPolicy(policy_str)
        sshares = util.calculateSharesList(s1, policy)
        ushares = util.calculateSharesList(u, policy)
        eshares = util.calculateSharesList(e, policy)
        eshares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in eshares])
        ushares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in ushares])
        sshares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in sshares])
        for attr, s_share in sshares.items():
            u_share = ushares[attr]
            e_share = eshares[attr]
            C5[attr] = s_share - ct['lambda'][attr]
            C6[attr] = u_share / ct['u'][attr]
            C7[attr] = e_share - ct['delta'][attr]
        CT = ct.copy()
        CT['CX1'] *= pair(pk_ser['X'], pk_ser['V']) ** (ct['theta'] * (u - ct['miu']))
        CT.update({'C0':C0, 'C5':C5, 'C6':C6, 'C7':C7, 'policy': policy_str})
        l = len(keywords)
        root_list = []
        IDX = {}
        for kw in keywords:
            root_i = ct['s2'] * gp['H2'](kw)
            root_list.append(root_i)
        p = self.getcoefroot(gp,root_list)
        p[str(0)] += 1
        if debug:
            tmp = self.evap(p, root_list)
            t = len(root_list)
            if tmp != group.init(ZR, len(root_list)):
                print("\npolynomial construction fails")
        for i in range(0,l+1):
            IDX[str(i)] = p[str(i)] / ct['n'][str(i)]
        del CT['theta']
        del CT['s2']
        del CT['lambda']
        del CT['u']
        del CT['miu']
        del CT['delta']
        del CT['n']
        CT.update({'W_II':IDX})
        return CT

    def Test(self, gp, tp, pk_ser, sk_ser, ct):
        '''test performed on the server'''
        usr_attribs = list(tp.keys())
        usr_attribs.remove('gid')
        usr_attribs.remove('z')
        usr_attribs.remove('num')
        usr_attribs.remove('T1')
        usr_attribs.remove('T2')
        usr_attribs.remove('T3')
        policy = util.createPolicy(ct['policy'])
        pruned = util.prune(policy, usr_attribs)
        if pruned == False:
            raise Exception("Don't have the required attributes for decryption!")
        coeffs = util.getCoefficients(policy)
        c4_right = 1

        for i in pruned:
            x = i.getAttributeAndIndex()
            c4 = ct['C4'][x] ** ct['C6'][x]
            c4_right *= (pair(c4, pk_ser['X'] ** tp['T1']) ** (coeffs[x] * sk_ser['v']))

        l = len(ct['W_II'])
        cw_left = 1

        for i in range(0, l):
            cw = ct['W_I'][str(i)] ** ct['W_II'][str(i)]
            cw_left *= (pair(cw, tp['T3'][str(i)] / (tp['T2'] ** sk_ser['x'])))

        cw_left *= (ct['CX1'] ** tp['T1'])

        return cw_left == c4_right


    def partial_decrypt(self, gp, tp, ct):
        '''Partial decryption launched on proxy'''
        usr_attribs = list(tp.keys())
        usr_attribs.remove('gid')
        usr_attribs.remove('z')
        usr_attribs.remove('T1')
        usr_attribs.remove('T2')
        usr_attribs.remove('T3')
        policy = util.createPolicy(ct['policy'])
        pruned = util.prune(policy, usr_attribs)
        if pruned == False:
            raise Exception("Don't have the required attributes for decryption!")
        coeffs = util.getCoefficients(policy)
        CP1 = 1
        CP2 = 1
        CP3 = pair(tp['gid'], gp['g'])
        egg = pair(gp['g'], gp['g'])
        for i in pruned:
            x = i.getAttributeAndIndex()
            y = i.getAttribute()
            c1 = ct['C1'][x] * ct['CS1'][x] * (egg ** ct['C5'][x])

            c3 = ct['C3'][x] * ct['CS2'][x] * (gp['g'] ** ct['C7'][x])

            num = pair(tp['gid'], c3) / pair(tp[y]['tk'], ct['C2'][x])
            CP1 *= (num ** coeffs[x])
            CP2 *= (c1 ** coeffs[x])
        return {'C0':ct['C0'], 'CP1':CP1, 'CP2':CP2, 'CP3':CP3}

    def full_decrypt(self, tk, ct):
        '''Decrypt a ciphertext on the user side
        SK is the user's private key dictionary {attr: { xxx , xxx }}
        '''
        c2 = ct['CP2'] ** ( tk['z'] ** -1 )
        ct_x = c2 * ct['CP1']
        ct_x /= ct['CP3']
        c_t = ct_x ** tk['z']
        return ct['C0'] / c_t

def main():
    arg_len = len(sys.argv)
    if arg_len == 1:
        sample_test = 1
    # Specify maximum number of the keywords
    total_kw_num = int(sys.argv[2])
    # Setup three authorities
    N = int(sys.argv[1])
    if debug:
        print("\nNumber of Authorities %d" % N)
        print("\nMax number of keywords %d" % total_kw_num)
    # Total number of attributes in universe
    with open('./attribute_set.pp', 'r') as fa:
        lists = fa.readlines()
    attrs_set = []
    for i in range(0, len(lists)):
        attrs_set.append(lists[i].rstrip('\n'))
    if debug:
        print("\nAttribute universe %s" % attrs_set)
    # GID of data user
    gid = sys.argv[3]
    # Number of user's attributes
    num_user_attr = int(sys.argv[4])
    usr_attrs = []
    for i in range(0, num_user_attr):
        usr_attrs.append(sys.argv[5 + i])
    if debug:
        print("\nUser's attribute %s" % usr_attrs)
    # Number of keywords for seaching
    num_kw = int(sys.argv[5 + num_user_attr])
    KW = []
    for i in range(0, num_kw):
        KW.append(sys.argv[6 + num_user_attr + i])
    if debug:
        print("\nKeywords for searching %s" % KW)
    # Number of keywords for index generation
    num_kw_idx = int(sys.argv[6 + num_user_attr + num_kw])
    keywords = []
    for i in range(0, num_kw_idx):
        keywords.append(sys.argv[7 + num_user_attr + num_kw + i])
    if debug:
        print("\nKeywords for index generation %s" % keywords)
    with open('./policy.pp', 'r') as f:
        lists = f.readlines()
        policy = lists[0].rstrip('\n')
    if debug: print('\nAcces Policy: %s' % policy)

    groupObj = PairingGroup('SS512')

    dabe = Dabe(groupObj)
    GP = dabe.setup()
    # Setup the server
    (sk_ser, pk_ser) = dabe.ser_setup(GP)

    SK, PK = {}, {}

    auth_attr_set = {}
    sstep = int(len(attrs_set) / N + 1)
    for i in range(0, N):
        auth_attr_set["authority"+str(i)] = attrs_set[i*sstep: min(len(attrs_set), (i + 1) * sstep)]
        (SK_i, PK_i) = dabe.authsetup(GP, auth_attr_set["authority"+str(i)])
        SK.update(SK_i)
        PK.update(PK_i)

    if debug: print("Authority SK")
    if debug: print(SK)

    # Generate data user
    K = {}
    # Generate user's attribute secret keys
    for i in range(0, N):
        intersection = list(set(auth_attr_set["authority"+str(i)]).intersection(set(usr_attrs)))
        if len(intersection):
            for j in intersection:
                dabe.keygen(GP, SK, j, gid, K)
    if debug:
        print("\nAttribute secret key of data user %s" % K)
        print("\nNumber of field elements in attribute secret key %d" % len(usr_attrs))
    # Transform the secret key
    TP = {}
    dabe.Trapdoor(GP,pk_ser,K,TP,KW,total_kw_num)
    if debug:
        print("\nTrapdoor %s" % TP)
        print("\nNumber of field elements in trapdoor %d" % (8 + 2 * len(usr_attrs) + 2 * total_kw_num))

    # Offline encryption
    offline_CT = dabe.offline_encrypt(GP, PK, pk_ser, attrs_set, total_kw_num)
    if debug:
        print("\nOffline Encryption %s" % offline_CT)
        #print("\nNumber of items in offline ciphertext %d" % len(offline_CT))
        print("\nNumber of field elements in offline ciphertext %d" % (8 + 15 * len(attrs_set) + 3 * total_kw_num))

    # Online encryption
    # Encrypt a random element in GT
    m = groupObj.random(GT)
    print("\nmessage is\n")
    print(m)
    CT = dabe.online_encrypt(GP, pk_ser, offline_CT, m, policy, keywords)
    if debug:
        print("\nFull Ciphertext %s" % CT)
        #print("\nNumber of items in full ciphertext %d" % len(CT))
        print("\nNumber of field elements in full ciphertext %d" % (3 * len(KW) + len(keywords) + 12 * len(attrs_set) + 4 + total_kw_num))
    # Conjunctive keyword search and decryption
    if dabe.Test(GP, TP, pk_ser, sk_ser, CT) != 1:
        print("\nConjunctive keyword search fails")
        return
    partial_ct = dabe.partial_decrypt(GP, TP, CT)
    if debug:
        print("\nPartial decryption: %s" % partial_ct)
    orig_m = dabe.full_decrypt(TP, partial_ct)

    assert m == orig_m, '\nFAILED Decryption!!!'
    print('\nSuccessful Decryption!')

if __name__ == '__main__':
    debug = False
    main()