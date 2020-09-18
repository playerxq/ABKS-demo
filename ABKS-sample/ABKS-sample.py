# Decentralized ABKS with expressive keyword search, online/offline encryption and outsourced decryption
# Author Xu Qian
# Data 2020-9
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import sys
import json
import os
import shutil
import numpy as np

debug = False

def get_files(path):
    files = []
    lsdir = os.listdir(path)
    for i in range(0, len(lsdir)):
        pp = os.path.join(path, lsdir[i])
        if os.path.isdir(pp):
            files.extend(get_files(pp))
        if os.path.isfile(pp):
            files.append(pp)
    return files

class DCP_ABKS(ABEncMultiAuth):

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
        H1 = lambda str: GP['g'] ** group.hash(str)
        # Hash used for keyword search
        H2 = lambda str: group.hash(str)
        GP['H1'] = H1
        GP['H2'] = H2
        return GP

    def setup(self):
        '''Global Setup'''
        #:In global setup, a bilinear group G of prime order p is chosen
        #:The global public parameters, GP and p, and a generator g of G. A random oracle H maps global identities GID to elements of G
        g = group.random(G1)
        gt = group.random(G1)
        #: The oracle that maps global identities GID onto elements of G
        H1 = lambda str: g**group.hash(str)
        # Hash used for keyword search
        H2 = lambda str: group.hash(str)
        #H = lambda x: group.hash(x, G1)
        GP = {'g': g, 'gt': gt, 'H1': H1, 'H2':H2}
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
            beta_i, gamma_i = group.random(), group.random()
            beta_i_inv = beta_i ** -1
            gamma_i_inv = gamma_i ** -1
            e_gg_alpha_i = pair(GP['g'], GP['g']) ** alpha_i
            g_y_i = GP['g'] ** y_i
            pk_i_0 = GP['g'] ** beta_i_inv
            pk_i_1 = GP['g'] ** gamma_i_inv
            SK[i.upper()] = {'alpha_i': alpha_i, 'y_i': y_i, 'beta_i': beta_i, 'gamma_i': gamma_i}
            PK[i.upper()] = {'e(gg)^alpha_i': e_gg_alpha_i, 'g^y_i': g_y_i, 'pk_i_0': pk_i_0, 'pk_i_1': pk_i_1}

        if (debug):
            print("Authority Setup for %s" % attributes)
            print("SK = {}".format(SK))
            print("PK = {}".format(PK))

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
    def keygen(self, gp, PK, sk, i, gid, tGID, skey):
        '''Create a key for GID on attribute i belonging to authority sk
        PK: server's public key
        sk: attribute secret key of authority
        i: attribute owned by user gid and meanwhile monitored by authority
        skey: attribute secret key of user gid computed by authority whose attribute set containing the user's attribute
        '''
        h = gp['H1'](gid)
        SK_0 = (gp['g'] ** sk[i.upper()]['alpha_i']) * (h ** sk[i.upper()]['y_i'])
        SK_1 = (PK['X'] ** (sk[i.upper()]['beta_i'] * (tGID ** -1))) * (h ** sk[i.upper()]['beta_i'])
        SK_2 = h ** sk[i.upper()]['gamma_i']
        skey[i.upper()] = {'SK_0': SK_0, 'SK_1': SK_1, 'SK_2': SK_2}
        skey['gid'] = gid
        skey['tGID'] = tGID
        if (debug):
            print("\nKey gen for %s on %s" % (gid, i))
            print("\nH(GID): '%s'" % h)
            print("\nSK = {}".format(skey))
        return None

    def get_Trapdoor_json(self, filename):
        with open(filename, 'r') as f:
            TP_json = json.load(f)
        TP = {}
        for i in TP_json.keys():
            if i == 'tp_5' or i == 'gid':
                TP[i] = group.deserialize(bytes(TP_json[i], encoding='utf-8'))
            elif i == 'tp_3' or i == 'tp_4':
                TP[i] = {}
                for k, v in TP_json[i].items():
                    TP[i].update({str(k): group.deserialize(bytes(v, encoding='utf-8'))})
            else:
                TP.update({i: {'tp_0': group.deserialize(bytes(TP_json[i]['tp_0'], encoding='utf-8')), 'tp_1': group.deserialize(bytes(TP_json[i]['tp_1'], encoding='utf-8')), 'tp_2': group.deserialize(bytes(TP_json[i]['tp_2'], encoding='utf-8'))}})
        return TP

    # Trapdoor
    def Trapdoor(self, gp, pk_ser, skey, query_policy, tp):
        '''Transform user's attribute secret key for outsourced decryption and search. Run on the user side'''
        zGID = group.random()
        skey.update({'zGID': zGID})
        T_3 = {}
        T_4 = {}
        tp['tp_5'] = gp['H1'](skey['gid']) ** zGID
        policy = util.createPolicy(query_policy)
        zshares = util.calculateSharesList(zGID, policy)
        zshares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in zshares])
        i = 1
        for kwi, z_share in zshares.items():
            T_3.update({'t_3_{}'.format(kwi): gp['H1'](skey['gid']) ** (z_share * gp['H2'](kwi))})
            T_4.update({'t_4_{}'.format(i): (gp['H1'](skey['gid']) ** skey['tGID']) * (pk_ser['X'] ** (-1 * gp['H2'](kwi)))})
            i += 1
        lw = i
        for key, value in skey.items():
            if key == 'gid':
                continue
            tp[key] = {'tp_0': value['SK_0'] ** zGID, 'tp_1': value['SK_1'] ** skey['tGID'], 'tp_2': value['SK_2'] ** skey['tGID']}
            if (debug):
                print("\nTP for attr %s = {}".format(tp[key]) % key)
        tp['tp_3'] = T_3
        tp['tp_4'] = T_4
        tp['pattern'] = query_policy  # for simplicity we embedded full policy into trapdoor
        tp['lw'] = lw
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

    def offline_encrypt(self, gp, pk, pk_ser, attributes):
        '''Performed on the data owner side'''
        # attributes: the attribute set required to generate the attribute policy. attributes will lead to the leakage of user's privacy in some cases and limit the scalability
        # pk: public keys of the authorities
        # pk_ser: public key of the server
        egg = pair(gp['g'], gp['g'])
        theta = group.random()
        C7 = gp['g'] ** theta
        C1, C2, C3, C4 = {}, {}, {}, {}
        IDX0, IDX1 = {}, {}
        IDS0, IDS1 = {}, {}
        CS0, CS1 = {}, {}
        C_lambda, C_delta, C_u = {}, {}, {}
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
            #  without loss of generality, assume a_i = ro_e_i
            C1[i.upper()] = (egg ** lambda_i) * (egg ** (alpha_i * r_i))
            C2[i.upper()] = gp['g'] ** r_i
            C3[i.upper()] = (gp['g'] ** (y_i * r_i)) * (gp['g'] ** delta_i)

            IDX0[i.upper()] = (pk[i.upper()]['pk_i_0'] ** (theta * (u_i + delta_i)))
            IDX1[i.upper()] = (pk[i.upper()]['pk_i_1'] ** (theta * u_i))

            IDS0[i.upper()] = (pk[i.upper()]['pk_i_0'] ** theta)
            IDS1[i.upper()] = (pk[i.upper()]['pk_i_1'] ** theta)

            CS0[i.upper()] = (pk[i.upper()]['e(gg)^alpha_i'] ** r_i) * (egg ** (-1 * (alpha_i * r_i)))
            CS1[i.upper()] = (pk[i.upper()]['g^y_i'] ** r_i) * gp['g'] ** (-1 * (y_i * r_i))

        return {'C1': C1, 'C2': C2, 'C3': C3, 'IDX0': IDX0, 'IDX1': IDX1, 'IDS0':IDS0, 'IDS1': IDS1, 'CS0': CS0, 'CS1': CS1, 'C7': C7, 'lambda': C_lambda, 'delta': C_delta, 'u': C_u, 'theta': theta}

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
        s2 = group.random()
        s3 = group.random()
        egg_s1 = pair(gp['g'], gp['g']) ** s1
        exv_theta_s2 = pair(pk_ser['X'], pk_ser['V']) ** (ct['theta'] * s2)  # this can be computed in off_line phase to improve the efficiency
        exv_theta_s3 = pair(pk_ser['X'], pk_ser['V']) ** (ct['theta'] * s3)  # this can be computed in off_line phase to improve the efficiency
        C0 = M * egg_s1
        C4, C5, C6 = {}, {}, {}
        policy = util.createPolicy(policy_str)
        s1shares = util.calculateSharesList(s1, policy)
        s2shares = util.calculateSharesList(s2, policy)
        s3shares = util.calculateSharesList(s3, policy)
        s1shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in s1shares])
        s2shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in s2shares])
        s3shares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in s3shares])
        for attr, s1_share in s1shares.items():
            s2_share = s2shares[attr]
            s3_share = s3shares[attr]
            C4[attr] = s1_share - ct['lambda'][attr]
            C5[attr] = s2_share - ct['u'][attr]
            C6[attr] = s3_share - ct['delta'][attr]
        CT = ct.copy()
        CT.update({'C0': C0, 'C4': C4, 'C5': C5, 'C6': C6, 'policy': policy_str})
        CT['C7'] = CT['C7'] ** s3
        #  encrypted keyword index
        KIDX = {'kidx_0': []}
        for i, kw in enumerate(keywords):
            h2w = gp['H2'](kw)
            KIDX['kw_{}'.format(i)] = kw  #  for simplicity, we insert keywords into the ciphertext for search
            KIDX['kidx_0'].append(exv_theta_s2 * (exv_theta_s3 ** h2w))
            KIDX['kidx_1_{}'.format(kw)] = gp['g'] ** (s3 * h2w)

        del CT['theta']
        del CT['lambda']
        del CT['u']
        del CT['delta']
        CT.update({'KIDX': KIDX})
        return CT

    def Search(self, gp, tp, pk_ser, sk_ser, ct):
        '''test performed on the server'''
        usr_attribs = list(tp.keys())
        usr_attribs.remove('gid')
        usr_attribs.remove('tp_3')
        usr_attribs.remove('tp_4')
        usr_attribs.remove('tp_5')
        usr_attribs.remove('pattern')
        policy = util.createPolicy(ct['policy'])
        pruned = util.prune(policy, usr_attribs)
        if pruned == False:
            raise Exception("Don't have the required attributes for decryption!")
        coeffs = util.getCoefficients(policy)

        TX = pair(ct['C7'], gp['gt']) ** (-1 * sk_ser['x'] * sk_ser['v'])

        for i in pruned:
            x = i.getAttributeAndIndex()
            y = i.getAttribute()
            TIDX_0 = ct['IDX0'][y.upper()] * (ct['IDS0'][y.upper()] ** (ct['C5'][y] + ct['C6'][y]))
            TIDX_1 = ct['IDX1'][y.upper()] * (ct['IDS1'][y.upper()] ** ct['C5'][y])
            TX *= (pair(TIDX_0, tp[y]['tp_1']) / pair(TIDX_1, tp[y]['tp_2'])) ** (sk_ser['v'] * coeffs[x])
        EIDX = []
        for i in range(tp['lw']):
            TX_i = TX / (pair(tp['tp_4']['t_4_{}'.format(i)], ct['C7']) ** sk_ser['v'])
            EIDX.append(TX_i)

        kwl = []
        intersection = ct['KIDX']['kidx_0'].intersection(EIDX)
        for i, v in enumerate(ct['KIDX']['kidx_0']):
            if v in intersection:
                kwl.append(ct['KIDX']['kw_{}'.format(i)])

        pattern = util.createPolicy(tp['pattern'])
        pruned_pattern = util.prune(pattern, kwl)
        if pruned_pattern == False:
            return 0
        coeffs_pattern = util.getCoefficients(tp['pattern'])
        return 1, pruned_pattern, coeffs_pattern


    def partial_decrypt(self, gp, tp, ct, pruned_pattern, coeffs_pattern):
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
        CP3 = 1
        egg = pair(gp['g'], gp['g'])
        for i in pruned:
            x = i.getAttributeAndIndex()
            y = i.getAttribute()
            c1 = ct['C1'][y.upper()] * ct['CS0'][y.upper()] * (egg ** ct['C4'][x])

            c3 = ct['C3'][y.upper()] * ct['CS1'][y.upper()] * (gp['g'] ** ct['C6'][x])

            num = pair(tp['tp_5'], c3) / pair(tp[y]['tp_0'], ct['C2'][y.upper()])
            CP1 *= (num ** coeffs[x])
            CP2 *= (c1 ** coeffs[x])

        for i in pruned_pattern:
            x = i.getAttributeAndIndex()
            y = i.getAttribute()
            CP3 *= (pair(tp['tp_3']['t_3_{}'.format(x)], ct['KIDX']['kidx_1_{}'.format(y)]) ** coeffs_pattern[x])
        return {'C0': ct['C0'], 'CP1': CP1, 'CP2': CP2, 'CP3': CP3}

    def full_decrypt(self, sk, ct):
        '''Decrypt a ciphertext on the user side
        SK is the user's private key dictionary {attr: { xxx , xxx }}
        '''
        c2 = ct['CP2'] ** sk['zGID']
        ct_x = c2 * ct['CP1']
        ct_x /= ct['CP3']
        c_t = ct_x ** (sk['zGID'] ** -1)
        return ct['C0'] / c_t

def main():
    arg_len = len(sys.argv)
    if arg_len == 1:
        sample_test = 1
    # Setup three authorities
    N = int(sys.argv[1])
    if debug:
        print("\nNumber of Authorities %d" % N)
    # Total number of attributes in universe
    with open('./attribute_set.pp', 'r') as fa:
        lists = fa.readlines()
    attrs_set = []
    for i in range(0, len(lists)):
        attrs_set.append(lists[i].rstrip('\n'))
    if debug:
        print("\nAttribute universe %s" % attrs_set)
    # GID of data user
    gid = sys.argv[2]
    # Number of user's attributes
    num_user_attr = int(sys.argv[3])
    usr_attrs = []
    for i in range(0, num_user_attr):
        usr_attrs.append(sys.argv[4 + i])
    if debug:
        print("\nUser's attribute %s" % usr_attrs)

    # Number of keywords for index generation
    num_kw_idx = int(sys.argv[4 + num_user_attr])
    keywords = []
    for i in range(0, num_kw_idx):
        keywords.append(sys.argv[4 + num_user_attr + i])
    if debug:
        print("\nKeywords for index generation %s" % keywords)
    with open('./policy.pp', 'r') as f:
        lists = f.readlines()
        policy = lists[0].rstrip('\n')
    if debug: print('\nAcces Policy: %s' % policy)

    with open('./pattern.pp', 'r') as f:
        lists = f.readlines()
        pattern = lists[0].rstrip('\n')
    if debug: print('\nQuery Pattern: %s' % pattern)

    groupObj = PairingGroup('SS512')

    dabe = DCP_ABKS(groupObj)
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
    tGID = group.random()
    # Generate user's attribute secret keys
    for i in range(0, N):
        intersection = list(set(auth_attr_set["authority"+str(i)]).intersection(set(usr_attrs)))
        if len(intersection):
            for j in intersection:
                dabe.keygen(GP, pk_ser, SK, j, gid, tGID, K)
    if debug:
        print("\nAttribute secret key of data user %s" % K)
        print("\nNumber of field elements in attribute secret key %d" % len(usr_attrs))
    # Transform the secret key
    TP = {}
    dabe.Trapdoor(GP, pk_ser, K, pattern, TP)
    if debug:
        print("\nTrapdoor {}".format(TP))

    # Offline encryption
    offline_CT = dabe.offline_encrypt(GP, PK, pk_ser, attrs_set)
    if debug:
        print("\nOffline Encryption {}".format(offline_CT))

    # Online encryption
    # Encrypt a random element in GT
    m = groupObj.random(GT)
    print("\nmessage is\n")
    print(m)
    CT = dabe.online_encrypt(GP, pk_ser, offline_CT, m, policy, keywords)
    if debug:
        print("\nFull Ciphertext %s" % CT)
    # Conjunctive keyword search and decryption
    res, pruned_pattern, coeffs_pattern = dabe.Search(GP, TP, pk_ser, sk_ser, CT)
    if res != 1:
        print("\nExpressive keyword search fails")
        return
    partial_ct = dabe.partial_decrypt(GP, TP, CT, pruned_pattern, coeffs_pattern)
    if debug:
        print("\nPartial decryption: %s" % partial_ct)
    orig_m = dabe.full_decrypt(K, partial_ct)

    assert m == orig_m, '\nFAILED Decryption!!!'
    print('\nSuccessful Decryption!')

if __name__ == '__main__':
    debug = False
    main()