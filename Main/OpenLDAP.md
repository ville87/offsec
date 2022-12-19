# OpenLDAP

## Read data
```
from ldap3 import Server, Connection, ObjectDef, AttrDef, Reader, Writer, ALL
server = Server('ldap.domain.local', port=389, get_info=ALL)
connection = Connection(server, 'uid=username,ou=users,ou=accounts,o=domain', 'SecretPassword123', auto_bind=True)
obj_person = ObjectDef('person', connection)

obj_inetorgperson = ObjectDef('inetOrgPerson', connection)
r = Reader(connection, obj_inetorgperson, 'ou=users,ou=accounts,o=domain')
r.search()
```

## Write data
```
w = Writer.from_cursor(r)
# change the password of the second entry
w[1].userPassword = 'SomeNewPassword123'
# verify changes
w[1].entry_changes
# commit changes
w.commit()
```
