from powsid import SID

sid1 = SID.lookup_accountname()
print((sid1, *sid1.lookup_accountsid()))

sid2 = SID.lookup_localcomputer()
print((sid2, *sid2.lookup_accountsid()))

sid3 = SID.lookup_currentuser()
print((sid3, *sid3.lookup_accountsid()))
