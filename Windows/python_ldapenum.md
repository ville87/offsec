# Enumerating LDAP with Python
```
from ldap3 import Server, Connection, ALL
server = Server('dc01.dumpsterfire.local', get_info=ALL)
conn = Connection(server, 'CN=john wayne,DC=dumpsterfire,DC=local', 'Somepass1', auto_bind=True)
conn.search('DC=dumpsterfire,DC=local', '(objectclass=person)')
conn.entries
```
