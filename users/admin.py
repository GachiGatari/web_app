from django.contrib import admin
from users.models import User, OneTimePassword, Role, Permission, LogUnit
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

class UserModelAdmin(BaseUserAdmin):
    # The fields to be used in displaying the User model.
    # These override the definitions on the base UserModelAdmin
    # that reference specific fields on users.User.
    list_display = ('id', 'email', 'name', 'is_admin', 'roles')
    list_filter = ('is_admin',)
    fieldsets = (
        ('User Credentials', {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('name',)}),
        ('Permissions', {'fields': ('is_admin', )}),
        ('Roles', {'fields': ('roles',)}),
    )
    filter_horizontal = ()
    # add_fieldsets is not a standard ModelAdmin attribute. UserModelAdmin
    # overrides get_fieldsets to use this attribute when creating a user.
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'name', 'password1', 'password2'),
        }),
    )
    search_fields = ('email',)
    ordering = ('email', 'id')
    filter_horizontal = ()

    @admin.display(description='roles')
    def roles(self, obj):
        return [role.name for role in obj.roles.all()]




# Now register the new UserModelAdmin...
admin.site.register(User, UserModelAdmin)
admin.site.register(OneTimePassword)
admin.site.register(Role)
admin.site.register(Permission)
admin.site.register(LogUnit)