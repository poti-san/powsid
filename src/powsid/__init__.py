import os as _os
from ctypes import (
    POINTER,
    Array,
    GetLastError,
    Structure,
    WinDLL,
    WinError,
    _Pointer,
    byref,
    c_byte,
    c_int32,
    c_size_t,
    c_uint,
    c_uint32,
    c_void_p,
    c_wchar,
    c_wchar_p,
)
from enum import IntEnum
from types import NotImplementedType
from typing import Final, NamedTuple, Sequence

assert _os.name == "nt", f"{__package__}はWindows環境で使用可能です。"


class WellKnownSIDType(IntEnum):
    """既知SID種類。"""

    NULL = 0
    WORLD = 1
    LOCAL = 2
    CREATOR_OWNER = 3
    CREATOR_GROUP = 4
    CREATOR_OWNER_SERVER = 5
    CREATOR_GROUP_SERVER = 6
    NT_AUTHORITY = 7
    DIALUP = 8
    NETWORK = 9
    BATCH = 10
    INTERACTIVE = 11
    SERVICE = 12
    ANONYMOUS = 13
    PROXY = 14
    ENTERPRISE_CONTROLLERS = 15
    SELF = 16
    AUTHENTICATED_USER = 17
    RESTRICTED_CODE = 18
    TERMINAL_SERVER = 19
    REMOTE_LOGON_ID = 20
    LOGON_IDS = 21
    LOCAL_SYSTEM = 22
    LOCAL_SERVICE = 23
    NETWORK_SERVICE = 24
    BUILTIN_DOMAIN = 25
    BUILTIN_ADMINISTRATORS = 26
    BUILTIN_USERS = 27
    BUILTIN_GUESTS = 28
    BUILTIN_POWER_USERS = 29
    BUILTIN_ACCOUNT_OPERATORS = 30
    BUILTIN_SYSTEM_OPERATORS = 31
    BUILTIN_PRINT_OPERATORS = 32
    BUILTIN_BACKUP_OPERATORS = 33
    BUILTIN_REPLICATOR = 34
    BUILTIN_PRE_WINDOWS2000_COMPATIBLE_ACCESS = 35
    BUILTIN_REMOTE_DESKTOP_USERS = 36
    BUILTIN_NETWORK_CONFIGURATION_OPERATORS = 37
    ACCOUNT_ADMINISTRATOR = 38
    ACCOUNT_GUEST = 39
    ACCOUNT_KRBTGT = 40
    ACCOUNT_DOMAIN_ADMINS = 41
    ACCOUNT_DOMAIN_USERS = 42
    ACCOUNT_DOMAIN_GUESTS = 43
    ACCOUNT_COMPUTERS = 44
    ACCOUNT_CONTROLLERS = 45
    ACCOUNT_CERT_ADMINS = 46
    ACCOUNT_SCHEMA_ADMINS = 47
    ACCOUNT_ENTERPRISE_ADMINS = 48
    ACCOUNT_POLICY_ADMINS = 49
    ACCOUNT_RAS_AND_IAS_SERVERS = 50
    NTLM_AUTHENTICATION = 51
    DIGEST_AUTHENTICATION = 52
    S_CHANNEL_AUTHENTICATION = 53
    THIS_ORGANIZATION = 54
    OTHER_ORGANIZATION = 55
    BUILTIN_INCOMING_FOREST_TRUST_BUILDERS = 56
    BUILTIN_PERF_MONITORING_USERS = 57
    BUILTIN_PERF_LOGGING_USERS = 58
    BUILTIN_AUTHORIZATION_ACCESS = 59
    BUILTIN_TERMINAL_SERVER_LICENSE_SERVERS = 60
    BUILTIN_DCOM_USERS = 61
    BUILTIN_I_USERS = 62
    I_USER = 63
    BUILTIN_CRYPTO_OPERATORS = 64
    UNTRUSTED_LABEL = 65
    LOW_LABEL = 66
    MEDIUM_LABEL = 67
    HIGH_LABEL = 68
    SYSTEM_LABEL = 69
    WRITE_RESTRICTED_CODE = 70
    CREATOR_OWNER_RIGHTS = 71
    CACHEABLE_PRINCIPALS_GROUP = 72
    NON_CACHEABLE_PRINCIPALS_GROUP = 73
    ENTERPRISE_READONLY_CONTROLLERS = 74
    ACCOUNT_READONLY_CONTROLLERS = 75
    BUILTIN_EVENT_LOG_READERS_GROUP = 76
    NEW_ENTERPRISE_READONLY_CONTROLLERS = 77
    BUILTIN_CERT_SVC_D_COM_ACCESS_GROUP = 78
    MEDIUM_PLUS_LABEL = 79
    LOCAL_LOGON = 80
    CONSOLE_LOGON = 81
    THIS_ORGANIZATION_CERTIFICATE = 82
    APPLICATION_PACKAGE_AUTHORITY = 83
    BUILTIN_ANY_PACKAGE = 84
    CAPABILITY_INTERNET_CLIENT = 85
    CAPABILITY_INTERNET_CLIENT_SERVER = 86
    CAPABILITY_PRIVATE_NETWORK_CLIENT_SERVER = 87
    CAPABILITY_PICTURES_LIBRARY = 88
    CAPABILITY_VIDEOS_LIBRARY = 89
    CAPABILITY_MUSIC_LIBRARY = 90
    CAPABILITY_DOCUMENTS_LIBRARY = 91
    CAPABILITY_SHARED_USER_CERTIFICATES = 92
    CAPABILITY_ENTERPRISE_AUTHENTICATION = 93
    CAPABILITY_REMOVABLE_STORAGE = 94
    BUILTIN_RDS_REMOTE_ACCESS_SERVERS = 95
    BUILTIN_RDS_ENDPOINT_SERVERS = 96
    BUILTIN_RDS_MANAGEMENT_SERVERS = 97
    USER_MODE_DRIVERS = 98
    BUILTIN_HYPER_V_ADMINS = 99
    ACCOUNT_CLONEABLE_CONTROLLERS = 100
    BUILTIN_ACCESS_CONTROL_ASSISTANCE_OPERATORS = 101
    BUILTIN_REMOTE_MANAGEMENT_USERS = 102
    AUTHENTICATION_AUTHORITY_ASSERTED = 103
    AUTHENTICATION_SERVICE_ASSERTED = 104
    LOCAL_ACCOUNT = 105
    LOCAL_ACCOUNT_AND_ADMINISTRATOR = 106
    ACCOUNT_PROTECTED_USERS = 107
    CAPABILITY_APPOINTMENTS = 108
    CAPABILITY_CONTACTS = 109
    ACCOUNT_DEFAULT_SYSTEM_MANAGED = 110
    BUILTIN_DEFAULT_SYSTEM_MANAGED_GROUP = 111
    BUILTIN_STORAGE_REPLICA_ADMINS = 112
    ACCOUNT_KEY_ADMINS = 113
    ACCOUNT_ENTERPRISE_KEY_ADMINS = 114
    AUTHENTICATION_KEY_TRUST = 115
    AUTHENTICATION_KEY_PROPERTY_MFA = 116
    AUTHENTICATION_KEY_PROPERTY_ATTESTATION = 117
    AUTHENTICATION_FRESH_KEY_AUTH = 118
    BUILTIN_DEVICE_OWNERS = 119
    BUILTIN_USER_MODE_HARDWARE_OPERATORS = 120
    BUILTIN_OPEN_SSH_USERS = 121


class SIDNameUse(IntEnum):
    """SID_NAME_USE列挙型"""

    USER = 1
    GROUP = 2
    DOMAIN = 3
    ALIAS = 4
    WELL_KNOWN_GROUP = 5
    DELETED_ACCOUNT = 6
    INVALID = 7
    UNKNOWN = 8
    COMPUTER = 9
    LABEL = 10
    LOGON_SESSION = 11


class _SID_IDENTIFIER_AUTHORITY(Structure):
    __slots__ = ()
    _fields_ = (("data", c_byte * 6),)


class SID:
    """Windowsのセキュリティ識別子。
    Examples:
        >>> sid1 = SID.create_wellknownsid(WellKnownSIDType.NT_AUTHORITY)
        >>> sid2 = SID.lookup_user()
        >>> sid3 = SID.lookup_computer()
        >>> sid4 = SID.lookup_accountsid(None, None)
    """

    CURRENT_REVISION: Final = 1
    """現在のリビジョン。"""

    MAX_SUB_AUTHORITIES: Final = 15
    """サブ認証値の最大個数。"""

    RECOMMENDED_SUB_AUTHORITIES: Final = 1
    """サブ認証値の推奨個数。"""

    __slots__ = "__data"
    __data: Array[c_byte]  # SIDのバイナリ表現

    def __init__(self, data: Array[c_byte]) -> None:
        """SIDのバイナリ表現を与えて初期化します。

        クラスは与えられた値をそのまま保持します。値を外部で変更する場合は複製を与えてください。"""
        self.__data = data

    def __len__(self) -> int:
        """SIDのバイナリ表現のバイト数を取得します。"""
        return len(self.__data)

    def __hash__(self) -> int:
        """SIDのバイナリ表現のハッシュを取得します。"""
        return hash(bytes(self.__data))

    @property
    def bytes(self) -> bytes:
        """SIDのバイト表現を取得します。"""
        return self.__data.value

    @staticmethod
    def create_wellknownsid(wellknownsidtype: int | WellKnownSIDType, domain_sid: "SID | None" = None) -> "SID":
        """既知のSIDを作成します。

        Args:
            wellknownsidtype (int | WellKnownSIDType): 既知SID種類。
            domain_sid (SID | None, optional): ドメインを識別するSID。Noneの場合はローカルコンピューターです。

        Raises:
            WinError: SIDの取得に失敗。
        """
        size = c_uint32()
        _CreateWellKnownSid(int(wellknownsidtype), domain_sid.bytes if domain_sid else None, None, byref(size))
        if size == 0:
            raise WinError()
        buf = (c_byte * size.value)()
        if not _CreateWellKnownSid(wellknownsidtype, domain_sid.bytes if domain_sid else None, buf, byref(size)):
            raise WinError()
        return SID(buf)

    def __str__(self) -> str:
        """文字列SIDを取得します。変換失敗時は空の文字列を返します。"""
        p = c_wchar_p()
        if not _ConvertSidToStringSidW(self.__data, byref(p)):
            raise WinError()
        try:
            return p.value or ""
        finally:
            _LocalFree(p)

    def __repr__(self) -> str:
        if len(self.__data) == 0:
            return "SID(<EMPTY>)"
        try:
            return f"SID({self.__str__()})"
        except Exception:
            return "SID(<ERROR>)"

    @staticmethod
    def from_strsid(s: str) -> "SID":
        """文字列SIDからSIDを作成します。

        Raises:
            WinError: 変換の失敗。
        """
        p = c_void_p()
        if not _ConvertStringSidToSidW(s, byref(p)):
            raise WinError()
        try:
            size: int = _LocalSize(p)
            if size == 0:
                raise WinError()
            t = c_byte * size
            return SID(t.from_buffer_copy(t.from_address(p.value or 0)))
        finally:
            _LocalFree(p)

    class AccountInfo(NamedTuple):
        """アカウント情報。"""

        name: str
        refdomainname: str
        use: SIDNameUse

    def lookup_accountsid(self, sysname: str | None = None) -> "SID.AccountInfo":
        """アカウント情報を取得します。

        Raises:
            WinError: 取得失敗。
        """
        namesize = c_uint32()
        refdomainnamesize = c_uint32()
        use = c_int32()
        if not _LookupAccountSidW(
            sysname, self.__data, None, byref(namesize), None, byref(refdomainnamesize), byref(use)
        ):
            if namesize.value == 0 and refdomainnamesize.value == 0 and use == 0:
                raise WinError()

        name = (c_wchar * namesize.value)()
        refdomainname = (c_wchar * refdomainnamesize.value)()
        if not _LookupAccountSidW(
            sysname, self.__data, name, byref(namesize), refdomainname, byref(refdomainnamesize), byref(use)
        ):
            raise WinError()

        return SID.AccountInfo(name.value, refdomainname.value, SIDNameUse(use.value))

    @property
    def domainsid(self) -> "SID":
        """ドメインSIDを取得します。

        Raises:
            WinError: 取得失敗。"""
        size = c_uint32()
        _GetWindowsAccountDomainSid(self.__data, None, byref(size))
        if size.value == 0:
            raise WinError()

        buf = (c_byte * size.value)()
        if not _GetWindowsAccountDomainSid(self.__data, buf, byref(size)):
            raise WinError()
        return SID(buf)

    def has_equal_domain(self, other: "SID") -> bool | NotImplementedType:
        """SIDのドメインが一致する場合は真を返します。"""
        if not isinstance(other, SID):
            return NotImplemented
        return _EqualDomainSid(self.__data, other.__data) != 0

    def is_wellknownsid(self, type: WellKnownSIDType | int) -> bool:
        """SIDが指定した種類の既知SIDの場合は真を返します。"""
        return _IsWellKnownSid(self.__data, int(type)) != 0

    @property
    def subauthcount(self) -> int:
        """サブ認証値数を取得・設定します。

        Raises:
            WinError: サブ認証値数の取得失敗。"""
        ret: _Pointer[c_byte] = _GetSidSubAuthorityCount(self.__data)
        if ret == 0 and GetLastError() != 0:
            raise WinError()
        return ret.contents.value

    @subauthcount.setter
    def subauthcount(self, value: int) -> None:
        ret: _Pointer[c_byte] = _GetSidSubAuthorityCount(self.__data)
        if ret == 0 and GetLastError() != 0:
            raise WinError()
        ret.contents.value = value

    def get_subsidauth_at(self, index: int) -> int:
        """指定位置のサブ認証値を取得します。

        Raises:
            WinError: 取得失敗。"""
        p: _Pointer[c_uint32] = _GetSidSubAuthority(self.__data, index)
        if p is None:
            raise WinError()
        return p.contents.value

    def set_subsidauth_at(self, index: int, value: int) -> None:
        """指定位置のサブ認証値を設定します。

        Raises:
            WinError: 設定失敗。"""
        p: _Pointer[c_uint32] = _GetSidSubAuthority(self.__data, index)
        if p is None:
            raise WinError()
        p.contents.value = value

    @property
    def subauths(self) -> list[int]:
        """サブ認証値を取得・設定します。

        Raises:
            WinError: 取得失敗。
            ValueError: 設定時のサブ認証値の個数不一致。"""
        return [self.get_subsidauth_at(i) for i in range(self.subauthcount)]

    @subauths.setter
    def subauths(self, values: Sequence[int]) -> None:
        subauthcount = self.subauthcount
        if len(values) != subauthcount:
            raise ValueError("SIDのサブ認証値と設定されるサブ認証値の数が一致しません。")
        for i in range(self.subauthcount):
            self.set_subsidauth_at(i, values[i])

    @property
    def is_valid(self) -> bool:
        """有効なSIDならば真を返します。"""
        return _IsValidSid(self.__data) != 0

    @property
    def identifyauth(self) -> int:
        """主要認証値を取得・設定します。

        Raises:
            WinError: 取得・設定失敗。
        """
        p: _Pointer[_SID_IDENTIFIER_AUTHORITY] = _GetSidIdentifierAuthority(self.__data)
        if p is None:
            raise WinError()
        return int.from_bytes(p.contents.data, "little")

    @identifyauth.setter
    def identifyauth(self, value: int) -> None:
        p: _Pointer[_SID_IDENTIFIER_AUTHORITY] = _GetSidIdentifierAuthority(self.__data)
        p.contents.data.value = value.to_bytes(6, "little")

    @staticmethod
    def get_required_len(subauth_count: int) -> int:
        """サブ認証値数からSIDに必要なバイト数を返します。"""
        return _GetSidLengthRequired(subauth_count)

    def __eq__(self, other) -> bool | NotImplementedType:
        """SIDが一致する場合は真、SIDが不一致する場合は偽、型が異なる場合はNotImplementedを返します。"""
        if isinstance(other, SID):
            return _EqualSid(self.__data, other.__data) != 0
        return NotImplemented

    def __ne__(self, other) -> bool | NotImplementedType:
        """SIDが不一致する場合は真、SIDが一致する場合は偽、型が異なる場合はNotImplementedを返します。"""
        if isinstance(other, SID):
            return _EqualSid(self.__data, other.__data) == 0
        return NotImplemented

    def has_equal_prefix(self, other: "SID") -> bool:
        """SIDの最後のサブ認証値以外が一致する場合は真を返します。"""
        return _EqualPrefixSid(self.__data, other.__data) != 0

    @staticmethod
    def lookup_accountname(accountname: str | None = None, sysname: str | None = None) -> "SID":
        """アカウント名からSIDを検索します。

        Args:
            accountname (str | None, optional): アカウント名。ドメイン名も指定する場合は「domain_name\\user_name」形式を用います。
            sysname (str | None, optional): リモートコンピューターの名前。Noneの場合はローカルコンピューターです。

        Raises:
            WinError: 検索の失敗。
        """
        sidsize = c_uint32()
        refdomainsize = c_uint32()
        use = c_int32()
        _LookupAccountNameW(sysname, accountname, None, byref(sidsize), None, byref(refdomainsize), byref(use))
        if sidsize.value == 0:
            raise WinError()

        sidbuf: Array[c_byte] = (c_byte * sidsize.value)()
        refdomainbuf: Array[c_wchar] = (c_wchar * refdomainsize.value)()
        if not _LookupAccountNameW(
            sysname, accountname, sidbuf, byref(sidsize), refdomainbuf, byref(refdomainsize), byref(use)
        ):
            raise WinError()
        return SID(sidbuf)

    @staticmethod
    def lookup_currentuser() -> "SID":
        """スレッドの現在のユーザーのSIDを検索します。

        Raises:
            WinError: 検索の失敗
        """
        return SID.lookup_accountname(SID.__get_username())

    @staticmethod
    def lookup_localcomputer() -> "SID":
        """ローカルコンピューターのSIDを検索します。

        Raises:
            WinError: 検索の失敗
        """
        return SID.lookup_accountname(SID.__get_computername())

    @staticmethod
    def from_auths(idauth: int, subauths: Sequence[int], revision_level: int = CURRENT_REVISION) -> "SID":
        return SID.from_strsid(f"S-{int(revision_level)}-{int(idauth)}-{"-".join(str(int(i)) for i in subauths)}")

    @staticmethod
    def __get_computername() -> str:
        bufsize = c_uint32()
        _GetComputerNameW(None, byref(bufsize))

        buf = (c_wchar * bufsize.value)()
        if not _GetComputerNameW(buf, byref(bufsize)):
            raise WinError()
        return buf.value

    @staticmethod
    def __get_username() -> str:
        bufsize = c_uint32()
        _GetUserNameW(None, byref(bufsize))

        buf = (c_wchar * bufsize.value)()
        if not _GetUserNameW(buf, byref(bufsize)):
            raise WinError()
        return buf.value


# windll汚染を避けるためにWinDLLインスタンスを保持します。
_advapi32 = WinDLL("advapi32.dll")
_kernel32 = WinDLL("kernel32.dll")

_GetLengthSid = _advapi32.GetLengthSid
_GetLengthSid.restype = c_uint32
_GetLengthSid.argtypes = (c_void_p,)

_CreateWellKnownSid = _advapi32.CreateWellKnownSid
_CreateWellKnownSid.argtypes = (c_int32, c_void_p, c_void_p, POINTER(c_uint32))

_ConvertStringSidToSidW = _advapi32.ConvertStringSidToSidW
_ConvertStringSidToSidW.argtypes = (c_wchar_p, POINTER(c_void_p))

_ConvertSidToStringSidW = _advapi32.ConvertSidToStringSidW
_ConvertSidToStringSidW.argtypes = (c_void_p, POINTER(c_wchar_p))

_LookupAccountSidW = _advapi32.LookupAccountSidW
_LookupAccountSidW.argtypes = (
    c_wchar_p,
    c_void_p,
    c_wchar_p,
    POINTER(c_uint32),
    c_wchar_p,
    POINTER(c_uint32),
    POINTER(c_int32),
)

_GetWindowsAccountDomainSid = _advapi32.GetWindowsAccountDomainSid
_GetWindowsAccountDomainSid.argtypes = (c_void_p, c_void_p, POINTER(c_uint32))

_IsWellKnownSid = _advapi32.IsWellKnownSid
_IsWellKnownSid.argtypes = (c_void_p, c_int32)

_EqualDomainSid = _advapi32.EqualDomainSid
_EqualDomainSid.argtypes = (c_void_p, c_void_p)

_GetSidSubAuthorityCount = _advapi32.GetSidSubAuthorityCount
_GetSidSubAuthorityCount.restype = POINTER(c_byte)
_GetSidSubAuthorityCount.argtypes = (c_void_p,)

_GetSidSubAuthority = _advapi32.GetSidSubAuthority
_GetSidSubAuthority.restype = POINTER(c_uint32)
_GetSidSubAuthority.argtypes = (c_void_p, c_uint)

_IsValidSid = _advapi32.IsValidSid
_IsValidSid.argtypes = (c_void_p,)

_GetSidIdentifierAuthority = _advapi32.GetSidIdentifierAuthority
_GetSidIdentifierAuthority.restype = POINTER(_SID_IDENTIFIER_AUTHORITY)
_GetSidIdentifierAuthority.argtypes = (c_void_p,)

_GetSidLengthRequired = _advapi32.GetSidLengthRequired
_GetSidLengthRequired.restype = c_uint32
_GetSidLengthRequired.argtypes = (c_byte,)

_EqualSid = _advapi32.EqualSid
_EqualSid.argtypes = (c_int32, c_int32)

_EqualPrefixSid = _advapi32.EqualPrefixSid
_EqualPrefixSid.argtypes = (c_int32, c_int32)

_LookupAccountNameW = _advapi32.LookupAccountNameW
_LookupAccountNameW.argtypes = (
    c_wchar_p,
    c_wchar_p,
    c_void_p,
    POINTER(c_uint32),
    c_wchar_p,
    POINTER(c_uint32),
    POINTER(c_int32),
)

_LocalFree = _kernel32.LocalFree
_LocalFree.restype = c_void_p
_LocalFree.argtypes = (c_void_p,)

_LocalSize = _kernel32.LocalSize
_LocalSize.restype = c_size_t
_LocalSize.argtypes = (c_void_p,)


_GetComputerNameW = _kernel32.GetComputerNameW
_GetComputerNameW.argtypes = (c_wchar_p, POINTER(c_uint32))

_GetUserNameW = _advapi32.GetUserNameW
_GetUserNameW.argtypes = (c_wchar_p, POINTER(c_uint32))
