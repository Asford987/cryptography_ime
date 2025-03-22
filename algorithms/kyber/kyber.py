

class Kyber:
    def __init__(self):
        self._generated = False
        self._pubkey = None
        self._privkey = None
    
    def generate_keypair(self, strength):
        self._generated = True
    
    @property
    def public_key(self):
        if not self._generated: raise RuntimeError("Key pair not generated") 
        return self._pubkey
    
    @property
    def private_key(self):
        if not self._generated: raise RuntimeError("Key pair not generated") 
        return self._privkey