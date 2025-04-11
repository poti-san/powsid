from powsid import SID

sid1 = SID.from_auths(1, (2, 3, 4, 5))
t = sid1.subauths
t[0] = 0x1234
sid1.subauths = t
print(sid1)
