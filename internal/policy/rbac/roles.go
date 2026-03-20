package rbac

const (
	RoleSuperAdmin   = "super_admin"
	RoleTenantAdmin  = "tenant_admin"
	RoleAppAdmin     = "app_admin"
	RoleAuditAdmin   = "audit_admin"
	RoleHelpdeskAdmin = "helpdesk_admin"
	RoleReadonlyAdmin = "readonly_admin"
)

var DefaultPlatformRoles = []string{
	RoleSuperAdmin,
	RoleTenantAdmin,
	RoleAppAdmin,
	RoleAuditAdmin,
	RoleHelpdeskAdmin,
	RoleReadonlyAdmin,
}

func IsPlatformRole(role string) bool {
	for _, candidate := range DefaultPlatformRoles {
		if candidate == role {
			return true
		}
	}

	return false
}
