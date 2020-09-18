def decrypt(self, C, D):
        policy = util.createPolicy(D['policy'])
        attrs = util.prune(policy, C['attributes'])
        if attrs == False:
            return False
        coeff = util.getCoefficients(policy)
        
        Z = {}
        prodT = 1
        for i in range(len(attrs)):
            x = attrs[i].getAttribute()
            y = attrs[i].getAttributeAndIndex()
            Z[y] = C['Ci'][x] ** D['Du'][x]
            prodT *= Z[y] ** coeff[y]
        
        symcrypt = SymmetricCryptoAbstraction(extractor(prodT))
        
        return symcrypt.decrypt(C['C'])
