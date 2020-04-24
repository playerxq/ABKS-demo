# Efficient decentralized attribute-based approach with online/offline encryption and outsourced decryption
# Author Xu Qian
# Data 2020-4-16
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth

debug = True


class Dabe(ABEncMultiAuth):

    def __init__(self, groupObj):
        ABEncMultiAuth.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)  # Create Secret Sharing Scheme
        group = groupObj  #:Prime order group

    def setup(self):
        '''Global Setup'''
        #:In global setup, a bilinear group G of prime order p is chosen
        #:The global public parameters, GP and p, and a generator g of G. A random oracle H maps global identities GID to elements of G

        g = group.random(G1)
        #: The oracle that maps global identities GID onto elements of G
        H = lambda str: g**group.hash(str)
        #H = lambda x: group.hash(x, G1)
        GP = {'g': g, 'H': H}

        return GP


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
            print("Key gen for %s on %s" % (gid, i))
            print("H(GID): '%s'" % h)
            print("K = g^alpha_i * H(GID) ^ y_i: %s" % K)
        return None

    # Transform secret key for outsourced decryption
    def Transform_sk(self, gp, skey, tkey):
        '''Transform user's attribute secret key for outsourced decryption. Run on the user side'''
        z = group.random()
        z_inv = z ** -1
        
        tkey['z'] = z
        tkey['gid'] = gp['H'](skey['gid']) ** z_inv
        if (debug): print("Transformed Key gen for %s" % skey['gid'])
        for key, value in skey.items():
            if key == 'gid':
                continue
            tkey[key] = {'tk': value['k'] ** z_inv}
            if (debug):
                print("TK for attr %s = %s" % (key,tkey[key]['tk']))
        return None

    def offline_encrypt(self, gp, pk, attributes):
        '''Performed on the data owner side'''
        # attributes: the attribute set required to generate the attribute policy. attributes will lead to the leakage of user's privacy in some cases
        # pk: public keys of the authorities
        egg = pair(gp['g'], gp['g'])
        C1, C2, C3 = {}, {}, {}
        CT1, CT2 = {}, {}
        C_lambda, C_omega = {}, {}
        C_alpha, C_r = {}, {}
        for i in attributes:
            lambda_i = group.random()
            alpha_i = group.random()
            y_i = group.random()
            omega_i = group.random()
            r_i = group.random()
            C_lambda[i.upper()] = lambda_i
            C_omega[i.upper()] = omega_i
            C1[i.upper()] = (egg ** lambda_i) * (egg ** (alpha_i * r_i))
            C2[i.upper()] = gp['g'] ** r_i
            C3[i.upper()] = (gp['g'] ** (y_i * r_i)) * (gp['g'] ** omega_i)
            CT1[i.upper()] =  (pk[i.upper()]['e(gg)^alpha_i'] ** r_i) * (egg ** (-1 * (alpha_i * r_i)))
            CT2[i.upper()] = (pk[i.upper()]['g^y_i'] ** r_i) * gp['g'] ** (-1 * (y_i * r_i))
            C_r[i.upper()] = r_i
            C_alpha[i.upper()] = alpha_i
        return {'C1':C1, 'C2':C2, 'C3':C3, 'CT1':CT1, 'CT2':CT2, 'lambda':C_lambda, 'omega':C_omega, 'alpha':C_alpha, 'r':C_r}

    def online_encrypt(self, gp, ct, M, policy_str):
        '''online encryption performed on the user side'''
        s = group.random()
        w = group.init(ZR, 0)
        egg_s = pair(gp['g'], gp['g']) ** s
        C0 = M * egg_s
        C4, C5 = {}, {}
        policy = util.createPolicy(policy_str)
        sshares = util.calculateSharesList(s, policy)
        wshares = util.calculateSharesList(w, policy)
        wshares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in wshares])
        sshares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in sshares])
        for attr, s_share in sshares.items():
            w_share = wshares[attr]
            C4[attr] = s_share - ct['lambda'][attr]
            C5[attr] = w_share - ct['omega'][attr]
        CT = ct.copy()
        CT.update({'C0':C0, 'C4':C4, 'C5':C5, 'policy': policy_str})
        return CT

    def partial_decrypt(self, gp, tk, ct):
        '''Partial decryption launched on proxy'''
        usr_attribs = list(tk.keys())
        usr_attribs.remove('gid')
        usr_attribs.remove('z')
        policy = util.createPolicy(ct['policy'])
        pruned = util.prune(policy, usr_attribs)
        if pruned == False:
            raise Exception("Don't have the required attributes for decryption!")
        coeffs = util.getCoefficients(policy)
        CT1 = 1
        CT2 = 1
        for i in pruned:
            x = i.getAttributeAndIndex()
            y = i.getAttribute()
            c1 = ct['C1'][x] * ct['CT1'][x]
            c1 = c1 * ( pair(gp['g'], gp['g']) ** ct['C4'][x] )
            c3 = ct['C3'][x] * ct['CT2'][x]
            c3 = c3 * ( gp['g'] ** ct['C5'][x] )
            num = pair(tk['gid'], c3) / pair(tk[y]['tk'], ct['C2'][x])
            CT1 *= (num ** coeffs[x])
            CT2 *= (c1 ** coeffs[x])
        return {'C0':ct['C0'], 'CT1':CT1, 'CT2':CT2}

    def full_decrypt(self, gp, tk, ct):
        '''Decrypt a ciphertext on the user side
        SK is the user's private key dictionary {attr: { xxx , xxx }}
        '''
        c2 = ct['CT2'] ** ( tk['z'] ** -1 )
        c_res = c2 * ct['CT1']
        c_t = c_res ** tk['z']
        return ct['C0'] / c_t

def main():
    groupObj = PairingGroup('SS512')

    dabe = Dabe(groupObj)
    GP = dabe.setup()
    SK, PK = {}, {}
    # Setup three authorities
    N = 3
    attrs_set = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE']
    auth_attr_set = {}
    for i in range(0, N):
        auth_attr_set["authority"+str(i)] = attrs_set[i*3: (i+1)*3]
        (SK_i, PK_i) = dabe.authsetup(GP, auth_attr_set["authority"+str(i)])
        if debug:
            SK.update(SK_i)
        PK.update(PK_i)

    if debug: print("Authority SK")
    if debug: print(SK)

    # Generate data user
    gid, K = "Bob", {}
    usr_attrs = ['ONE', 'THREE', 'FIVE', 'SEVEN']
    if debug: print('User credential list: %s' % usr_attrs)
    # Generate user's attribute secret keys
    for i in range(0, N):
        intersection = list(set(auth_attr_set["authority"+str(i)]).intersection(set(usr_attrs)))
        if len(intersection):
            for j in intersection:
                dabe.keygen(GP, SK, j, gid, K)
    # Transform the secret key
    TK = {}
    dabe.Transform_sk(GP, K,TK)
    
    # Encrypt a random element in GT
    m = groupObj.random(GT)
    policy = '((one or two) AND (three or four) AND (seven))'
    if debug: print('Acces Policy: %s' % policy)
    offline_CT = dabe.offline_encrypt(GP, PK, attrs_set)
    CT = dabe.online_encrypt(GP, offline_CT, m, policy)
    partial_ct = dabe.partial_decrypt(GP, TK, CT)
    orig_m = dabe.full_decrypt(GP, TK, partial_ct)

    assert m == orig_m, 'FAILED Decryption!!!'
    if debug: print('Successful Decryption!')


if __name__ == '__main__':
    debug = True
    main()