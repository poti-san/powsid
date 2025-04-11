# 既知SIDの名前・ドメイン名・用途を取得する。

from powsid import SID, WellKnownSIDType

for sidtype in WellKnownSIDType:
    try:
        sid = SID.create_wellknownsid(WellKnownSIDType(sidtype))
        print((sid, *sid.lookup_accountsid()))
    except Exception:
        pass
