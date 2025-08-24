import mongoose from "mongoose";

export function applyInstanceMethods(schema) {
  // Método principal para verificar permisos
  schema.methods.hasPermission = function (resource, action, scope = "own") {
    if (!this.isActive || this.isExpired) {
      return false;
    }

    const permission = this.permissions.find(
      (p) => p.resource === resource || p.resource === "all"
    );

    if (!permission) {
      return false;
    }

    const hasAction =
      permission.actions.includes(action) ||
      permission.actions.includes("manage") ||
      permission.actions.includes("all");

    if (!hasAction) {
      return false;
    }

    // Verificar scope
    const scopeHierarchy = ["none", "own", "company", "global"];
    const requiredScopeLevel = scopeHierarchy.indexOf(scope);
    const permissionScopeLevel = scopeHierarchy.indexOf(permission.scope);

    return permissionScopeLevel >= requiredScopeLevel;
  };

  // Método para verificar permisos con contexto geográfico
  schema.methods.hasPermissionWithLocation = function (
    resource,
    action,
    scope = "own",
    location = null
  ) {
    if (!this.hasPermission(resource, action, scope)) {
      return false;
    }

    // Verificar restricciones geográficas globales del rol
    if (this.geographicRestrictions.restrictToGeolocation && location) {
      return this.checkGeographicRestrictions(
        location.country,
        location.region
      );
    }

    // Verificar restricciones específicas del permiso
    const permission = this.permissions.find(
      (p) => p.resource === resource || p.resource === "all"
    );

    if (permission?.geographicRestrictions?.restrictToLocation && location) {
      const restrictions = permission.geographicRestrictions;

      if (restrictions.allowedCountries?.length > 0) {
        return restrictions.allowedCountries.includes(location.country);
      }

      if (restrictions.allowedRegions?.length > 0) {
        return restrictions.allowedRegions.includes(location.region);
      }
    }

    return true;
  };

  // Añadir permiso
  schema.methods.addPermission = function (
    resource,
    actions,
    scope = "own",
    conditions = {}
  ) {
    const existingPermissionIndex = this.permissions.findIndex(
      (p) => p.resource === resource
    );

    const permission = {
      resource,
      actions: Array.isArray(actions) ? actions : [actions],
      scope,
      conditions,
      geographicRestrictions: {
        restrictToLocation: false,
      },
      timeRestrictions: {
        businessHoursOnly: false,
      },
    };

    if (existingPermissionIndex >= 0) {
      this.permissions[existingPermissionIndex] = permission;
    } else {
      this.permissions.push(permission);
    }

    return this;
  };

  // Eliminar permiso
  schema.methods.removePermission = function (resource, action = null) {
    if (action) {
      const permission = this.permissions.find((p) => p.resource === resource);
      if (permission) {
        permission.actions = permission.actions.filter((a) => a !== action);
        if (permission.actions.length === 0) {
          this.permissions = this.permissions.filter(
            (p) => p.resource !== resource
          );
        }
      }
    } else {
      this.permissions = this.permissions.filter(
        (p) => p.resource !== resource
      );
    }

    return this;
  };

  // Verificar gestión de empresa
  schema.methods.canManageCompany = function (companyId = null) {
    if (!this.isActive || this.isExpired) {
      return false;
    }

    const restrictions = this.companyRestrictions;

    if (restrictions.canManageAllCompanies) {
      return true;
    }

    if (
      companyId &&
      restrictions.allowedCompanies &&
      restrictions.allowedCompanies.length > 0
    ) {
      return restrictions.allowedCompanies.some((id) => id.equals(companyId));
    }

    return !restrictions.restrictedToOwnCompany;
  };

  // Verificar restricciones geográficas
  schema.methods.checkGeographicRestrictions = function (
    country = null,
    region = null
  ) {
    if (!this.geographicRestrictions.restrictToGeolocation) {
      return true;
    }

    const restrictions = this.geographicRestrictions;

    if (
      country &&
      restrictions.allowedCountries &&
      restrictions.allowedCountries.length > 0
    ) {
      if (!restrictions.allowedCountries.includes(country.toUpperCase())) {
        return false;
      }
    }

    if (
      region &&
      restrictions.allowedRegions &&
      restrictions.allowedRegions.length > 0
    ) {
      if (!restrictions.allowedRegions.includes(region)) {
        return false;
      }
    }

    return true;
  };

  // Obtener configuración de sesión efectiva
  schema.methods.getEffectiveSessionConfig = function () {
    const defaultConfig = {
      maxConcurrentSessions: 3,
      sessionTimeoutMinutes: 480,
      requireTwoFactor: false,
      allowRememberMe: true,
    };

    return {
      ...defaultConfig,
      ...this.sessionConfig,
    };
  };

  // Verificar si requiere aprobación
  schema.methods.requiresApprovalFor = function (resource, action) {
    const permission = this.permissions.find(
      (p) => p.resource === resource || p.resource === "all"
    );

    if (!permission) return false;

    // Acciones que siempre requieren aprobación para ciertos roles
    const criticalActions = ["delete", "manage", "admin"];
    const requiresApprovalActions =
      permission.conditions?.requiresApproval || [];

    return (
      (criticalActions.includes(action) && this.hierarchy < 80) ||
      requiresApprovalActions.includes(action)
    );
  };

  // Obtener resumen de permisos
  schema.methods.getPermissionsSummary = function () {
    const summary = {
      totalPermissions: this.permissions.length,
      resourcesWithFullAccess: [],
      resourcesWithLimitedAccess: [],
      scopeDistribution: { none: 0, own: 0, company: 0, global: 0 },
      securityLevel: this.securityLevel,
      requiresTwoFactor: this.sessionConfig?.requireTwoFactor || false,
    };

    this.permissions.forEach((permission) => {
      if (
        permission.actions.includes("manage") ||
        permission.actions.includes("all")
      ) {
        summary.resourcesWithFullAccess.push(permission.resource);
      } else {
        summary.resourcesWithLimitedAccess.push({
          resource: permission.resource,
          actions: permission.actions,
        });
      }

      summary.scopeDistribution[permission.scope]++;
    });

    return summary;
  };
}
