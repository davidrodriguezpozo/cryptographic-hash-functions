class RSAMethod():

    def __init__(self, p_in, q_in):
        self.p = p_in
        self.q = q_in
        self._N = self.p*self.q
        self.phi = (self.p-1)*(self.q-1)
        self._e = None
        self._d = None

    @property
    def p(self):
        return self._p

    @p.setter
    def p(self, val):
        if(val == 0):
            raise Exception("Value can't be 0")
        self.checkPrime(val)
        self._p = val

    @property
    def q(self):
        return self._q

    @q.setter
    def q(self, val):
        if(val == 0):
            raise Exception("Value can't be 0")
        self.checkPrime(val)
        self._q = val

    @property
    def e(self):
        return self._e

    @e.setter
    def e(self, val):
        for i in range(2, self.phi):
            if(val % i == 0 and i % self.phi == 0):
                raise Exception(f'e is not coprime with {self.phi}')
        self._e = val

    @property
    def d(self):
        return self._d

    @d.setter
    def d(self, val):
        if(val*self.e % self.phi != 1):
            raise Exception(
                f"{val} times {self.e} divided by {self.phi} has not 1 as residual.")
        self._d = val

    # Methods

    def __str__(self):
        return f"""Values are: \n Primes: {self.p}, {self.q} \n N is {self._N} \n Phi is {self.phi} \n e is {self.e} \n d is {self.d}"""

    def publicKey(self):
        if(self.e is None):
            raise Exception('e is not set')
        return (self.p*self.q, self.e)

    def privateKey(self):
        if(self.e is None or self.d is None):
            raise Exception("e or d are not set")
        return (self.p*self.q, self.d)

    def encodeMessage(self, M: int) -> int:
        return (M**self.e) % self._N

    def decodeMessage(self, D: int) -> int:
        return (D**self.d) % self._N

    @staticmethod
    def checkPrime(val):
        if val > 1:
            for i in range(2, val//2):
                if (val % i) == 0:
                    raise Exception(f'{val} is not a prime number')
        else:
            raise Exception(f'{val} is not greater than 1')


if(__name__ == '__main__'):
    print(""" 
        This is an encrypting RSA method test. In order for it to work, remember than the message can only be enctrypted if it is smaller (bitwise), than 
        the range of bytes of p and q). The larger p and q are, the bigger the message can be.
    """)
    p = int(input("Set first prime "))
    q = int(input("Set second prime "))
    rsa = RSAMethod(p, q)
    rsa.e = int(input(f"Now choose a coprime of {rsa.phi} "))
    rsa.d = int(input(f"Now choose d such that d * e = 1 mod {rsa.phi} "))
    M = int(input("Select a message (integer). Remember that it can't be larger (in bytes) than the primes selected, or it won't be encrypted correctly."))
    encoded = rsa.encodeMessage(M)
    decoded = rsa.decodeMessage(encoded)
