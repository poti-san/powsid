Search.setIndex({"alltitles":{"Module contents":[[0,"module-powsid"]],"powsid package":[[0,null]],"powsid\u30d1\u30c3\u30b1\u30fc\u30b8":[[1,null]],"\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb":[[1,"id1"]]},"docnames":["apiref/powsid","index"],"envversion":{"sphinx":65,"sphinx.domains.c":3,"sphinx.domains.changeset":1,"sphinx.domains.citation":1,"sphinx.domains.cpp":9,"sphinx.domains.index":1,"sphinx.domains.javascript":3,"sphinx.domains.math":2,"sphinx.domains.python":4,"sphinx.domains.rst":2,"sphinx.domains.std":2},"filenames":["apiref\\powsid.rst","index.md"],"indexentries":{},"objects":{"":[[0,0,0,"-","powsid"]],"powsid":[[0,1,1,"","SID"],[0,1,1,"","SIDNameUse"],[0,1,1,"","WellKnownSIDType"]],"powsid.SID":[[0,1,1,"","AccountInfo"],[0,2,1,"","CURRENT_REVISION"],[0,2,1,"","MAX_SUB_AUTHORITIES"],[0,2,1,"","RECOMMENDED_SUB_AUTHORITIES"],[0,3,1,"","bytes"],[0,4,1,"","create_wellknownsid"],[0,3,1,"","domainsid"],[0,4,1,"","from_auths"],[0,4,1,"","from_strsid"],[0,4,1,"","get_required_len"],[0,4,1,"","get_subsidauth_at"],[0,4,1,"","has_equal_domain"],[0,4,1,"","has_equal_prefix"],[0,3,1,"","identifyauth"],[0,3,1,"","is_valid"],[0,4,1,"","is_wellknownsid"],[0,4,1,"","lookup_accountname"],[0,4,1,"","lookup_accountsid"],[0,4,1,"","lookup_currentuser"],[0,4,1,"","lookup_localcomputer"],[0,4,1,"","set_subsidauth_at"],[0,3,1,"","subauthcount"],[0,3,1,"","subauths"]],"powsid.SID.AccountInfo":[[0,2,1,"","name"],[0,2,1,"","refdomainname"],[0,2,1,"","use"]],"powsid.SIDNameUse":[[0,2,1,"","ALIAS"],[0,2,1,"","COMPUTER"],[0,2,1,"","DELETED_ACCOUNT"],[0,2,1,"","DOMAIN"],[0,2,1,"","GROUP"],[0,2,1,"","INVALID"],[0,2,1,"","LABEL"],[0,2,1,"","LOGON_SESSION"],[0,2,1,"","UNKNOWN"],[0,2,1,"","USER"],[0,2,1,"","WELL_KNOWN_GROUP"]],"powsid.WellKnownSIDType":[[0,2,1,"","ACCOUNT_ADMINISTRATOR"],[0,2,1,"","ACCOUNT_CERT_ADMINS"],[0,2,1,"","ACCOUNT_CLONEABLE_CONTROLLERS"],[0,2,1,"","ACCOUNT_COMPUTERS"],[0,2,1,"","ACCOUNT_CONTROLLERS"],[0,2,1,"","ACCOUNT_DEFAULT_SYSTEM_MANAGED"],[0,2,1,"","ACCOUNT_DOMAIN_ADMINS"],[0,2,1,"","ACCOUNT_DOMAIN_GUESTS"],[0,2,1,"","ACCOUNT_DOMAIN_USERS"],[0,2,1,"","ACCOUNT_ENTERPRISE_ADMINS"],[0,2,1,"","ACCOUNT_ENTERPRISE_KEY_ADMINS"],[0,2,1,"","ACCOUNT_GUEST"],[0,2,1,"","ACCOUNT_KEY_ADMINS"],[0,2,1,"","ACCOUNT_KRBTGT"],[0,2,1,"","ACCOUNT_POLICY_ADMINS"],[0,2,1,"","ACCOUNT_PROTECTED_USERS"],[0,2,1,"","ACCOUNT_RAS_AND_IAS_SERVERS"],[0,2,1,"","ACCOUNT_READONLY_CONTROLLERS"],[0,2,1,"","ACCOUNT_SCHEMA_ADMINS"],[0,2,1,"","ANONYMOUS"],[0,2,1,"","APPLICATION_PACKAGE_AUTHORITY"],[0,2,1,"","AUTHENTICATED_USER"],[0,2,1,"","AUTHENTICATION_AUTHORITY_ASSERTED"],[0,2,1,"","AUTHENTICATION_FRESH_KEY_AUTH"],[0,2,1,"","AUTHENTICATION_KEY_PROPERTY_ATTESTATION"],[0,2,1,"","AUTHENTICATION_KEY_PROPERTY_MFA"],[0,2,1,"","AUTHENTICATION_KEY_TRUST"],[0,2,1,"","AUTHENTICATION_SERVICE_ASSERTED"],[0,2,1,"","BATCH"],[0,2,1,"","BUILTIN_ACCESS_CONTROL_ASSISTANCE_OPERATORS"],[0,2,1,"","BUILTIN_ACCOUNT_OPERATORS"],[0,2,1,"","BUILTIN_ADMINISTRATORS"],[0,2,1,"","BUILTIN_ANY_PACKAGE"],[0,2,1,"","BUILTIN_AUTHORIZATION_ACCESS"],[0,2,1,"","BUILTIN_BACKUP_OPERATORS"],[0,2,1,"","BUILTIN_CERT_SVC_D_COM_ACCESS_GROUP"],[0,2,1,"","BUILTIN_CRYPTO_OPERATORS"],[0,2,1,"","BUILTIN_DCOM_USERS"],[0,2,1,"","BUILTIN_DEFAULT_SYSTEM_MANAGED_GROUP"],[0,2,1,"","BUILTIN_DEVICE_OWNERS"],[0,2,1,"","BUILTIN_DOMAIN"],[0,2,1,"","BUILTIN_EVENT_LOG_READERS_GROUP"],[0,2,1,"","BUILTIN_GUESTS"],[0,2,1,"","BUILTIN_HYPER_V_ADMINS"],[0,2,1,"","BUILTIN_INCOMING_FOREST_TRUST_BUILDERS"],[0,2,1,"","BUILTIN_I_USERS"],[0,2,1,"","BUILTIN_NETWORK_CONFIGURATION_OPERATORS"],[0,2,1,"","BUILTIN_OPEN_SSH_USERS"],[0,2,1,"","BUILTIN_PERF_LOGGING_USERS"],[0,2,1,"","BUILTIN_PERF_MONITORING_USERS"],[0,2,1,"","BUILTIN_POWER_USERS"],[0,2,1,"","BUILTIN_PRE_WINDOWS2000_COMPATIBLE_ACCESS"],[0,2,1,"","BUILTIN_PRINT_OPERATORS"],[0,2,1,"","BUILTIN_RDS_ENDPOINT_SERVERS"],[0,2,1,"","BUILTIN_RDS_MANAGEMENT_SERVERS"],[0,2,1,"","BUILTIN_RDS_REMOTE_ACCESS_SERVERS"],[0,2,1,"","BUILTIN_REMOTE_DESKTOP_USERS"],[0,2,1,"","BUILTIN_REMOTE_MANAGEMENT_USERS"],[0,2,1,"","BUILTIN_REPLICATOR"],[0,2,1,"","BUILTIN_STORAGE_REPLICA_ADMINS"],[0,2,1,"","BUILTIN_SYSTEM_OPERATORS"],[0,2,1,"","BUILTIN_TERMINAL_SERVER_LICENSE_SERVERS"],[0,2,1,"","BUILTIN_USERS"],[0,2,1,"","BUILTIN_USER_MODE_HARDWARE_OPERATORS"],[0,2,1,"","CACHEABLE_PRINCIPALS_GROUP"],[0,2,1,"","CAPABILITY_APPOINTMENTS"],[0,2,1,"","CAPABILITY_CONTACTS"],[0,2,1,"","CAPABILITY_DOCUMENTS_LIBRARY"],[0,2,1,"","CAPABILITY_ENTERPRISE_AUTHENTICATION"],[0,2,1,"","CAPABILITY_INTERNET_CLIENT"],[0,2,1,"","CAPABILITY_INTERNET_CLIENT_SERVER"],[0,2,1,"","CAPABILITY_MUSIC_LIBRARY"],[0,2,1,"","CAPABILITY_PICTURES_LIBRARY"],[0,2,1,"","CAPABILITY_PRIVATE_NETWORK_CLIENT_SERVER"],[0,2,1,"","CAPABILITY_REMOVABLE_STORAGE"],[0,2,1,"","CAPABILITY_SHARED_USER_CERTIFICATES"],[0,2,1,"","CAPABILITY_VIDEOS_LIBRARY"],[0,2,1,"","CONSOLE_LOGON"],[0,2,1,"","CREATOR_GROUP"],[0,2,1,"","CREATOR_GROUP_SERVER"],[0,2,1,"","CREATOR_OWNER"],[0,2,1,"","CREATOR_OWNER_RIGHTS"],[0,2,1,"","CREATOR_OWNER_SERVER"],[0,2,1,"","DIALUP"],[0,2,1,"","DIGEST_AUTHENTICATION"],[0,2,1,"","ENTERPRISE_CONTROLLERS"],[0,2,1,"","ENTERPRISE_READONLY_CONTROLLERS"],[0,2,1,"","HIGH_LABEL"],[0,2,1,"","INTERACTIVE"],[0,2,1,"","I_USER"],[0,2,1,"","LOCAL"],[0,2,1,"","LOCAL_ACCOUNT"],[0,2,1,"","LOCAL_ACCOUNT_AND_ADMINISTRATOR"],[0,2,1,"","LOCAL_LOGON"],[0,2,1,"","LOCAL_SERVICE"],[0,2,1,"","LOCAL_SYSTEM"],[0,2,1,"","LOGON_IDS"],[0,2,1,"","LOW_LABEL"],[0,2,1,"","MEDIUM_LABEL"],[0,2,1,"","MEDIUM_PLUS_LABEL"],[0,2,1,"","NETWORK"],[0,2,1,"","NETWORK_SERVICE"],[0,2,1,"","NEW_ENTERPRISE_READONLY_CONTROLLERS"],[0,2,1,"","NON_CACHEABLE_PRINCIPALS_GROUP"],[0,2,1,"","NTLM_AUTHENTICATION"],[0,2,1,"","NT_AUTHORITY"],[0,2,1,"","NULL"],[0,2,1,"","OTHER_ORGANIZATION"],[0,2,1,"","PROXY"],[0,2,1,"","REMOTE_LOGON_ID"],[0,2,1,"","RESTRICTED_CODE"],[0,2,1,"","SELF"],[0,2,1,"","SERVICE"],[0,2,1,"","SYSTEM_LABEL"],[0,2,1,"","S_CHANNEL_AUTHENTICATION"],[0,2,1,"","TERMINAL_SERVER"],[0,2,1,"","THIS_ORGANIZATION"],[0,2,1,"","THIS_ORGANIZATION_CERTIFICATE"],[0,2,1,"","UNTRUSTED_LABEL"],[0,2,1,"","USER_MODE_DRIVERS"],[0,2,1,"","WORLD"],[0,2,1,"","WRITE_RESTRICTED_CODE"]]},"objnames":{"0":["py","module","Python \u30e2\u30b8\u30e5\u30fc\u30eb"],"1":["py","class","Python \u30af\u30e9\u30b9"],"2":["py","attribute","Python \u306e\u5c5e\u6027"],"3":["py","property","Python \u30d7\u30ed\u30d1\u30c6\u30a3"],"4":["py","method","Python \u30e1\u30bd\u30c3\u30c9"]},"objtypes":{"0":"py:module","1":"py:class","2":"py:attribute","3":"py:property","4":"py:method"},"terms":{"\")":[],"\"{":[],"(\"":[],"((":1,"()":[0,1],"(f":[],"(guid":[],"(none":0,"(scheme":[],"(setting":[],"(sidtype":1,"(subgroup":[],"(wellknownsidtype":[0,1],"({":[],"))":1,"--":0,"-bf":[],"-f":[],".ac":[],".active":[],".apply":[],".create":[0,1],".friendlyname":[],".from":[],".iter":[],".lookup":[0,1],".nosubgroup":[],".nt":0,".ps1":1,".setting":[],".settings":[],"0aad":[],"0bcb":[],"1c":[],"4b":[],"4d":[],"4f":[],"5d":[],"5e":[],"7e":[],"8b":[],"8c":[],"8de":[],"8f":[],"9a":[],"9b":[],"9e":[],"9fa":[],"9fd":[],">>":0,"_access":0,"_account":[0,1],"_accountname":[0,1],"_accountsid":[0,1],"_active":[],"_administrator":0,"_administrators":0,"_admins":0,"_and":0,"_any":0,"_appointments":0,"_asserted":0,"_assistance":0,"_at":0,"_attestation":0,"_auth":0,"_authentication":0,"_authorities":0,"_authority":0,"_authorization":0,"_auths":0,"_backup":0,"_battery":[],"_brightness":[],"_builders":0,"_button":[],"_cacheable":0,"_cert":0,"_certificate":0,"_certificates":0,"_changes":[],"_channel":0,"_client":0,"_cloneable":0,"_code":0,"_com":0,"_computer":0,"_computers":0,"_configuration":0,"_contacts":0,"_control":0,"_controllers":0,"_count":0,"_crypto":0,"_currentuser":[0,1],"_d":0,"_dcom":0,"_default":0,"_defined":[],"_description":[],"_descriptor":[],"_desktop":0,"_device":0,"_disk":[],"_display":[],"_documents":0,"_domain":0,"_drivers":0,"_endpoint":0,"_enterprise":0,"_equal":0,"_event":0,"_ex":[],"_filename":[],"_forest":0,"_fresh":0,"_friendly":[],"_group":0,"_guest":0,"_guests":0,"_guid":[],"_hardware":0,"_hyper":0,"_i":0,"_ias":0,"_id":0,"_ids":0,"_incoming":0,"_index":[],"_indexes":[],"_individual":[],"_internet":0,"_key":0,"_known":0,"_krbtgt":0,"_label":0,"_len":0,"_level":0,"_library":0,"_license":0,"_list":[],"_localcomputer":[0,1],"_log":0,"_logging":0,"_logon":0,"_managed":0,"_management":0,"_mfa":0,"_mode":0,"_monitoring":0,"_music":0,"_name":0,"_nameuser":0,"_network":0,"_open":0,"_operators":0,"_organization":0,"_owner":0,"_owners":0,"_package":0,"_pciexpress":[],"_perf":0,"_pictures":0,"_platform":[],"_plus":0,"_policy":0,"_possible":[],"_power":0,"_pre":0,"_prefix":0,"_principals":0,"_print":0,"_private":0,"_processorsettings":[],"_property":0,"_protected":0,"_range":[],"_ras":0,"_rds":0,"_readers":0,"_readonly":0,"_ref":[],"_remote":0,"_removable":0,"_replica":0,"_replicator":0,"_required":0,"_requirements":[],"_resource":[],"_restore":[],"_restricted":0,"_revision":0,"_rights":0,"_role":[],"_schema":0,"_scheme":[],"_server":0,"_servers":0,"_service":0,"_session":0,"_setting":[],"_settings":[],"_shared":0,"_sid":0,"_size":[],"_sleep":[],"_specifier":[],"_ssh":0,"_storage":0,"_str":[],"_strsid":0,"_sub":0,"_subgroup":[],"_subgroups":[],"_subsidauth":0,"_svc":0,"_sysbutton":[],"_system":0,"_terminal":0,"_trust":0,"_type":[],"_use":0,"_user":0,"_users":0,"_v":0,"_valid":0,"_value":[],"_version":[],"_videos":0,"_wellknownsid":[0,1],"_windows":0,"`none":[],"ac":[],"account":0,"accountinfo":0,"accountname":0,"active":[],"aded":[],"af":[],"alias":0,"anonymous":0,"appliancepc":[],"application":0,"apply":[],"array":0,"as":[],"authenticated":0,"authentication":0,"batch":0,"battery":[],"be":[],"binary":[],"bool":0,"builtin":0,"byref":[],"bytes":0,"cacheable":0,"can":[],"capability":0,"cc":[],"class":0,"compatible":0,"computer":0,"console":0,"contents":1,"create":0,"creator":0,"current":0,"dac":[],"data":0,"dc":[],"delete":[],"deleted":0,"description":[],"descriptions":[],"desktop":[],"dialup":0,"digest":0,"disk":[],"display":[],"domain":0,"domainsid":0,"duplicate":[],"ed":[],"ee":[],"eebd":[],"enterprise":0,"enterpriseserver":[],"enumerate":[],"except":1,"exception":1,"expand":[],"express":[],"fba":[],"fea":[],"field":0,"final":0,"for":[0,1],"friendly":[],"friendlyname":[],"from":[0,1],"full":[],"get":0,"group":0,"guid":[],"has":0,"high":0,"iconres":[],"idauth":0,"identifyauth":0,"import":1,"in":1,"index":0,"install":1,"int":0,"intenum":0,"interactive":0,"invalid":0,"is":0,"iter":[],"iterator":[],"label":0,"le":[],"link":[],"list":0,"local":0,"logon":0,"lookup":[0,1],"low":0,"max":0,"maximum":[],"medium":0,"mobile":[],"module":1,"multi":[],"name":0,"namedtuple":0,"network":0,"new":0,"no":[],"non":0,"none":0,"nosubgroup":[],"notimplementedtype":0,"nt":0,"ntlm":0,"null":0,"number":0,"object":0,"optional":0,"other":0,"package":1,"pass":1,"pci":[],"pciexpress":[],"performanceserver":[],"pip":1,"platform":[],"power":[],"powerentry":[],"powerknownsubgroupguid":[],"powerplatform":[],"powerplatformrole":[],"powerpossiblesetting":[],"powerscheme":[],"powersetting":[],"powersettingvalue":[],"powersettingvaluetype":[],"powersubgroup":[],"powguid":[],"print":1,"processor":[],"property":0,"proxy":0,"python":1,"raises":0,"raw":[],"recommended":0,"refdomainname":0,"remote":0,"resource":[],"restricted":0,"revision":0,"scheme":[],"self":0,"sequence":0,"service":0,"set":0,"setting":[],"settings":[],"sid":[0,1],"sidnameuse":[0,1],"sidtype":1,"slate":[],"sleep":[],"sohoserver":[],"static":0,"str":0,"subauth":0,"subauthcount":0,"subauths":0,"subgroup":[],"subgroups":[],"sysname":0,"system":0,"terminal":0,"this":0,"true":[],"try":1,"type":0,"uint":[],"unknown":0,"unspecified":[],"untrusted":0,"use":0,"user":0,"value":0,"valueerror":0,"values":0,"well":0,"wellknownsidtype":[0,1],"windows":[0,1],"winerror":0,"workstation":[],"world":0,"write":0,"}\"":[],"})":[],"\u300cdomain":0,"\u3042\u308c":[],"\u3044\u308c":[],"\u304b\u3089":[0,1],"\u304f\u3060":1,"\u3055\u3044":1,"\u3059\u308b":[0,1],"\u305d\u308c\u305e\u308c":[],"\u3067\u3059":[0,1],"\u3068\u3057":1,"\u3068\u3057\u3066":1,"\u306a\u3044":[],"\u306a\u3089":0,"\u306e\u307f":1,"\u307e\u3059":[0,1],"\u307e\u305f":[],"\u3084\u3059\u304f":1,"\u3088\u3046":[],"\u308c\u308b":[],"\u30a2\u30ab\u30a6\u30f3\u30c8":0,"\u30a2\u30af\u30c6\u30a3\u30d6":[],"\u30a4\u30c6\u30ec\u30fc\u30bf\u30fc":[],"\u30a4\u30df\u30e5\u30fc\u30bf\u30d6\u30eb":[],"\u30a4\u30f3\u30c7\u30c3\u30af\u30b9":[],"\u30a8\u30e9\u30fc":[],"\u30af\u30e9\u30b9":[],"\u30b3\u30f3\u30bb\u30f3\u30c8":[],"\u30b3\u30fc\u30c9":[],"\u30b5\u30d6":0,"\u30b5\u30d6\u30b0\u30eb\u30fc\u30d7":[],"\u30b5\u30d6\u30b0\u30eb\u30fc\u30d7guid":[],"\u30b5\u30f3\u30d7\u30eb":0,"\u30b7\u30b9\u30c6\u30e0\u30dc\u30bf\u30f3":[],"\u30b9\u30ad\u30fc\u30e0":[],"\u30b9\u30ea\u30fc\u30d7":[],"\u30b9\u30ec\u30c3\u30c9":0,"\u30bb\u30ad\u30e5\u30ea\u30c6\u30a3":0,"\u30bb\u30ad\u30e5\u30ea\u30c6\u30a3id":1,"\u30c0\u30a6\u30f3\u30ed\u30fc\u30c9":1,"\u30c7\u30a3\u30b9\u30af":[],"\u30c7\u30a3\u30b9\u30d7\u30ec\u30a4":[],"\u30c9\u30e1\u30a4\u30f3":0,"\u30c9\u30e1\u30a4\u30f3sid":0,"\u30d0\u30a4\u30c8":0,"\u30d0\u30c3\u30c6\u30ea\u30fc":[],"\u30d1\u30e9\u30e1\u30fc\u30bf":0,"\u30d3\u30c7\u30aa":[],"\u30d5\u30ec\u30f3\u30c9\u30ea\u30fc":[],"\u30d7\u30ed\u30bb\u30c3\u30b5\u30fc":[],"\u30d9\u30fc\u30b9\u30af\u30e9\u30b9":0,"\u30e6\u30fc\u30b6\u30fc":[0,1],"\u30e9\u30a4\u30d6\u30e9\u30ea":1,"\u30ea\u30d3\u30b8\u30e7\u30f3":0,"\u30ea\u30e2\u30fc\u30c8\u30b3\u30f3\u30d4\u30e5\u30fc\u30bf\u30fc":0,"\u30ed\u30fc\u30ab\u30eb\u30b3\u30f3\u30d4\u30e5\u30fc\u30bf\u30fc":[0,1],"\u30ed\u30fc\u30ab\u30eb\u30d1\u30c3\u30b1\u30fc\u30b8":1,"\u30fb\u30c9\u30e1\u30a4\u30f3":1,"\u4e00\u81f4":0,"\u4e0d\u4e00\u81f4":0,"\u4e3b\u8981":0,"\u4ea4\u6d41":[],"\u4ee5\u5916":[],"\u4f4d\u7f6e":0,"\u4f5c\u6210":0,"\u4f7f\u3044":1,"\u4f7f\u7528":1,"\u4f8b\u5916":0,"\u4f9d\u5b58":1,"\u4fdd\u6301":[],"\u500b\u6570":0,"\u5024\u4ee5":0,"\u5024\u578b":[],"\u5024\u6570":0,"\u5217\u6319":0,"\u5229\u7528":1,"\u524d\u63d0":1,"\u53cd\u6620":[],"\u53d6\u308a\u5f97\u308b":[],"\u53d6\u5f97":[0,1],"\u540c\u3058":[],"\u540d\u524d":[0,1],"\u57fa\u672c":[],"\u5834\u5408":0,"\u5909\u63db":0,"\u5909\u66f4":[],"\u5931\u6557":0,"\u5b9a\u7fa9":[],"\u5b9f\u884c":1,"\u5b9f\u969b":[],"\u5bfe\u5fdc":[],"\u5f62\u5f0f":0,"\u5fc5\u8981":0,"\u60c5\u5831":0,"\u6210\u5426":[],"\u6240\u5c5e":[],"\u6307\u5b9a":0,"\u63a5\u7d9a":[],"\u63a8\u5968":0,"\u64cd\u4f5c":[],"\u6587\u5b57\u5217":0,"\u65e2\u77e5":0,"\u65e2\u77e5sid":[0,1],"\u660e\u308b":[],"\u66f8\u3051":[],"\u6700\u5927":0,"\u6700\u5f8c":0,"\u6709\u52b9":0,"\u691c\u7d22":0,"\u6a19\u6e96":1,"\u6a5f\u80fd":[],"\u73fe\u5728":0,"\u7528\u3044":0,"\u7528\u9014":1,"\u753b\u9762":[],"\u756a\u76ee":[],"\u76f4\u4e0b":[],"\u76f4\u63a5":[],"\u76f4\u6d41":[],"\u78ba\u8a8d":[],"\u7a2e\u985e":0,"\u7a3c\u50cd":[],"\u7ba1\u7406":[],"\u7bc4\u56f2":[],"\u7c21\u5358":[],"\u8868\u3059":[],"\u8868\u73fe":0,"\u8a2d\u5b9a":0,"\u8a8d\u8a3c":0,"\u8aac\u660e":[],"\u8b58\u5225":0,"\u8b58\u5225\u5b50":0,"\u8fd4\u3057":0,"\u8fd4\u3059":[],"\u96fb\u529b":[],"\u96fb\u6e90":[],"\u9806\u756a":[]},"titles":["powsid package","powsid\u30d1\u30c3\u30b1\u30fc\u30b8"],"titleterms":{"contents":0,"module":0,"package":0,"powpowerman":[],"powsid":[0,1],"\u30a4\u30f3\u30b9\u30c8\u30fc\u30eb":1,"\u30d1\u30c3\u30b1\u30fc\u30b8":1}})