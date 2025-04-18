# powsidパッケージ

```{toctree}
---
hidden:
---
apiref/powsid
genindex
modindex
```

PythonからWindowsのSID（セキュリティID）を使いやすくするパッケージです。標準ライブラリのみに依存します。

**既知SIDの名前・ドメイン名・用途を取得する。**
```python
from powsid import SID, WellKnownSIDType

for sidtype in WellKnownSIDType:
    try:
        sid = SID.create_wellknownsid(WellKnownSIDType(sidtype))
        print((sid, *sid.lookup_account()))
    except Exception:
        pass
```

**ローカルコンピューターやユーザーのSIDを取得する**
```python
from powsid import SID

sid1 = SID.lookup_accountname()
print((sid1, *sid1.lookup_accountsid()))

sid2 = SID.lookup_localcomputer()
print((sid2, *sid2.lookup_accountsid()))

sid3 = SID.lookup_currentuser()
print((sid3, *sid3.lookup_accountsid()))
```

## インストール

ローカルパッケージとしての利用を前提としています。使用時はダウンロードして`pip install e.ps1`を実行してください。
