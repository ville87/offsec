# All Stuff LDAP queries
## PowerShell ADSI
Check out [PowerShell ADSI](PS_ADSI.md)

## DSQuery
```
dsquery user
dsquery * -filter “(&(objectclass=computer)(name=*win*))” -attr name samaccountname -d 192.168.88.195
dsquery * -filter “(&(objectclass=user)(!(objectclass=computer)(name=*W*)))” -attr name samaccountname -d 192.168.88.195
dsquery group -name *admin* -d 192.168.88.195
dsquery * -filter “(&(objectclass=group)(name=*admin*))” -attr name samaccountname -d 192.168.88.195
dsquery * -filter “(&(objectclass=group)(samaccountname=Domain Admins))” -attr name samaccountname member -d 192.168.88.195
dsquery computer -name *DC* -d 192.168.88.195
dsquery * -filter “(&(objectclass=computer)(name=*DC*))” -attr name samaccountname operatingsystem -d 192.168.88.195
dsquery * -filter “(description=*password*)” -attr name description -d 192.168.88.195
dsquery * -filter “(&(objectclass=user)(pwdlastset<=132655849658851779))” -attr name pwdlastset -d 192.168.88.195
dsquery * -filter “(&(memberof=CN=Staff,DC=PLANETEXPRESS,DC=LOCAl)(memberof=CN=ShipCrew,DC=PLANETEXPRESS,DC=LOCAL))” -attr name memberof -d 192.168.88.195
```

## ldapsearch
```
ldapsearch -LLL -x -h DC-THESHIP.PLANETEXPRESS.LOCAL -p 389 -D ‘PLANETEXPRESS\SService’ -w ‘L1feD3@thSeamlessContinuum’ -b ‘DC=PLANETEXPRESS,DC=LOCAL’ “(&(objectclass=group)(name=*admin*))” name samaccountname
ldapsearch -LLL -x -h DC-THESHIP.PLANETEXPRESS.LOCAL -p 389 -D ‘PLANETEXPRESS\SService’ -w ‘L1feD3@thSeamlessContinuum’ -b ‘DC=PLANETEXPRESS,DC=LOCAL’ “(&(objectclass=computer)(name=*DC*))” name samaccountname operatingsystem
ldapsearch -LLL -x -h DC-THESHIP.PLANETEXPRESS.LOCAL -p 389 -D ‘PLANETEXPRESS\SService’ -w ‘L1feD3@thSeamlessContinuum’ -b ‘DC=PLANETEXPRESS,DC=LOCAL’ “(description=*password*)” name description
ldapsearch -LLL -x -h DC-THESHIP.PLANETEXPRESS.LOCAL -p 389 -D ‘PLANETEXPRESS\SService’ -w ‘L1feD3@thSeamlessContinuum’ -b ‘DC=PLANETEXPRESS,DC=LOCAL’ “(&(objectclass=user)(pwdlastset<=132655849658851779))” name pwdlastset
ldapsearch -LLL -x -h DC-THESHIP.PLANETEXPRESS.LOCAL -p 389 -D ‘PLANETEXPRESS\SService’ -w ‘L1feD3@thSeamlessContinuum’ -b ‘DC=PLANETEXPRESS,DC=LOCAL’ “(&(memberof=CN=Staff,DC=PLANETEXPRESS,DC=LOCAl)(memberof=CN=ShipCrew,DC=PLANETEXPRESS,DC=LOCAL))” name memberof
```
