from django.dispatch import Signal

# providing_args=['allocation', 'user', 'username']
openportal_association_created = Signal()

# providing_args=['allocation', 'user']
openportal_association_deleted = Signal()
