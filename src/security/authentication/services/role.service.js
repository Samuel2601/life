// =============================================================================
// src/modules/authentication/services/role.service.js
// =============================================================================
import { RoleRepository } from "../repositories/role.repository.js";
import { UserRepository } from "../repositories/user.repository.js";
import {
  AuthError,
  AuthErrorCodes,
  AuthConstants,
} from "../authentication.index.js";
import { TransactionHelper } from "../../../utils/transsaccion.helper.js";

export class RoleService {
  constructor() {
    this.roleRepository = new RoleRepository();
    this.userRepository = new UserRepository();
  }

  /**
   * Crear nuevo rol
   * @param {Object} roleData - Datos del rol
   * @param {Object} requestInfo - Información del request
   */
  async createRole(roleData, requestInfo) {
    try {
      const { userId, ipAddress, userAgent } = requestInfo;

      // Validar permisos del usuario para crear roles
      await this.validateUserPermission(userId, "roles", "create", "global");

      // Validar datos del rol
      this.validateRoleData(roleData);

      const userData = {
        userId,
        ip: ipAddress,
        userAgent,
      };

      const newRole = await this.roleRepository.createRole(roleData, userData);

      console.log(`✅ Rol creado: ${newRole.roleName} por usuario ${userId}`);

      return {
        success: true,
        role: newRole,
      };
    } catch (error) {
      console.error("Error creando rol:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Error creando rol",
        AuthErrorCodes.ROLE_CREATION_FAILED,
        500
      );
    }
  }

  /**
   * Actualizar rol existente
   * @param {string} roleId - ID del rol
   * @param {Object} updateData - Datos a actualizar
   * @param {Object} requestInfo - Información del request
   */
  async updateRole(roleId, updateData, requestInfo) {
    try {
      const { userId, ipAddress, userAgent } = requestInfo;

      // Validar permisos
      await this.validateUserPermission(userId, "roles", "update", "global");

      // Verificar que el rol existe
      const existingRole = await this.roleRepository.findById(roleId);
      if (!existingRole) {
        throw new AuthError(
          "Rol no encontrado",
          AuthErrorCodes.ROLE_NOT_FOUND,
          404
        );
      }

      // No permitir modificar roles del sistema críticos
      if (
        existingRole.isSystemRole &&
        ["super_admin", "admin"].includes(existingRole.roleName)
      ) {
        const userRoles = await this.getUserRoles(userId);
        const isSuperAdmin = userRoles.some(
          (role) => role.roleName === "super_admin"
        );

        if (!isSuperAdmin) {
          throw new AuthError(
            "No se pueden modificar roles críticos del sistema",
            AuthErrorCodes.PERMISSION_DENIED,
            403
          );
        }
      }

      // Validar datos de actualización
      if (updateData.permissions) {
        this.validatePermissions(updateData.permissions);
      }

      const userData = {
        userId,
        ip: ipAddress,
        userAgent,
      };

      const updatedRole = await this.roleRepository.update(
        roleId,
        updateData,
        userData
      );

      console.log(
        `✅ Rol actualizado: ${existingRole.roleName} por usuario ${userId}`
      );

      return {
        success: true,
        role: updatedRole,
      };
    } catch (error) {
      console.error("Error actualizando rol:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Error actualizando rol",
        AuthErrorCodes.ROLE_UPDATE_FAILED,
        500
      );
    }
  }

  /**
   * Asignar rol a usuario
   * @param {string} userId - ID del usuario
   * @param {string} roleId - ID del rol
   * @param {Object} requestInfo - Información del request
   */
  async assignRoleToUser(userId, roleId, requestInfo) {
    return await TransactionHelper.executeWithOptionalTransaction(
      async (session) => {
        try {
          const { userId: adminUserId, ipAddress, userAgent } = requestInfo;

          // Validar permisos del administrador
          await this.validateUserPermission(
            adminUserId,
            "users",
            "update",
            "global"
          );

          // Verificar que el usuario existe
          const user = await this.userRepository.findById(userId);
          if (!user) {
            throw new AuthError(
              "Usuario no encontrado",
              AuthErrorCodes.USER_NOT_FOUND,
              404
            );
          }

          // Verificar que el rol existe y está activo
          const role = await this.roleRepository.findById(roleId);
          if (!role || !role.isActive) {
            throw new AuthError(
              "Rol no encontrado o inactivo",
              AuthErrorCodes.ROLE_NOT_FOUND,
              404
            );
          }

          // Verificar si el usuario ya tiene el rol
          if (user.roles && user.roles.includes(roleId)) {
            throw new AuthError(
              "El usuario ya tiene asignado este rol",
              AuthErrorCodes.ROLE_ALREADY_ASSIGNED,
              409
            );
          }

          // Validar límites del rol
          if (role.maxUsers && role.stats.userCount >= role.maxUsers) {
            throw new AuthError(
              "El rol ha alcanzado el límite máximo de usuarios",
              AuthErrorCodes.ROLE_USER_LIMIT_EXCEEDED,
              409
            );
          }

          // Verificar restricciones geográficas si aplican
          if (role.geographicRestrictions?.restrictToGeolocation) {
            // Aquí podrías agregar lógica para validar la ubicación del usuario
            // Por ahora, asumimos que es válida
          }

          const userData = {
            userId: adminUserId,
            ip: ipAddress,
            userAgent,
          };

          // Asignar rol
          await this.roleRepository.assignRole(userId, roleId, userData);

          console.log(
            `✅ Rol ${role.roleName} asignado a usuario ${userId} por ${adminUserId}`
          );

          return {
            success: true,
            message: `Rol '${role.displayName}' asignado exitosamente`,
            assignedRole: {
              roleId: role._id,
              roleName: role.roleName,
              displayName: role.displayName,
              hierarchy: role.hierarchy,
            },
          };
        } catch (error) {
          console.error("Error asignando rol:", error);
          if (error instanceof AuthError) {
            throw error;
          }
          throw new AuthError(
            "Error asignando rol al usuario",
            AuthErrorCodes.ROLE_ASSIGNMENT_FAILED,
            500
          );
        }
      }
    );
  }

  /**
   * Remover rol de usuario
   * @param {string} userId - ID del usuario
   * @param {string} roleId - ID del rol
   * @param {Object} requestInfo - Información del request
   */
  async removeRoleFromUser(userId, roleId, requestInfo) {
    return await TransactionHelper.executeWithOptionalTransaction(
      async (session) => {
        try {
          const { userId: adminUserId, ipAddress, userAgent } = requestInfo;

          // Validar permisos del administrador
          await this.validateUserPermission(
            adminUserId,
            "users",
            "update",
            "global"
          );

          // Verificar que el usuario existe
          const user = await this.userRepository.findById(userId);
          if (!user) {
            throw new AuthError(
              "Usuario no encontrado",
              AuthErrorCodes.USER_NOT_FOUND,
              404
            );
          }

          // Verificar que el usuario tiene el rol
          if (!user.roles || !user.roles.includes(roleId)) {
            throw new AuthError(
              "El usuario no tiene asignado este rol",
              AuthErrorCodes.ROLE_NOT_ASSIGNED,
              409
            );
          }

          // Verificar que el rol existe
          const role = await this.roleRepository.findById(roleId);
          if (!role) {
            throw new AuthError(
              "Rol no encontrado",
              AuthErrorCodes.ROLE_NOT_FOUND,
              404
            );
          }

          // No permitir remover el último rol de un usuario
          if (user.roles.length === 1) {
            const defaultRole = await this.roleRepository.getDefaultRole();
            if (defaultRole && !defaultRole._id.equals(roleId)) {
              // Asignar rol por defecto antes de remover el actual
              await this.roleRepository.assignRole(userId, defaultRole._id, {
                userId: adminUserId,
                ip: ipAddress,
                userAgent,
              });
            } else {
              throw new AuthError(
                "No se puede remover el único rol del usuario",
                AuthErrorCodes.CANNOT_REMOVE_LAST_ROLE,
                409
              );
            }
          }

          const userData = {
            userId: adminUserId,
            ip: ipAddress,
            userAgent,
          };

          // Remover rol
          await this.roleRepository.removeRole(userId, roleId, userData);

          console.log(
            `✅ Rol ${role.roleName} removido de usuario ${userId} por ${adminUserId}`
          );

          return {
            success: true,
            message: `Rol '${role.displayName}' removido exitosamente`,
            removedRole: {
              roleId: role._id,
              roleName: role.roleName,
              displayName: role.displayName,
            },
          };
        } catch (error) {
          console.error("Error removiendo rol:", error);
          if (error instanceof AuthError) {
            throw error;
          }
          throw new AuthError(
            "Error removiendo rol del usuario",
            AuthErrorCodes.ROLE_REMOVAL_FAILED,
            500
          );
        }
      }
    );
  }

  /**
   * Verificar permisos de usuario
   * @param {string} userId - ID del usuario
   * @param {string} resource - Recurso
   * @param {string} action - Acción
   * @param {string} scope - Alcance requerido
   * @param {Object} context - Contexto adicional
   */
  async checkUserPermission(
    userId,
    resource,
    action,
    scope = "own",
    context = {}
  ) {
    try {
      const userRoles = await this.getUserRoles(userId);

      if (!userRoles || userRoles.length === 0) {
        return {
          hasPermission: false,
          reason: "Usuario sin roles asignados",
        };
      }

      // Verificar permisos en todos los roles del usuario
      for (const role of userRoles) {
        const hasPermission = await this.roleRepository.hasPermission(
          role._id,
          resource,
          action,
          scope
        );

        if (hasPermission) {
          // Verificar restricciones adicionales
          const restrictionCheck = this.checkRoleRestrictions(role, context);

          if (restrictionCheck.isValid) {
            return {
              hasPermission: true,
              grantedBy: role.roleName,
              scope: this.getEffectiveScope(role, resource, action),
            };
          }
        }
      }

      return {
        hasPermission: false,
        reason: "Permisos insuficientes",
        requiredPermission: `${action} on ${resource} with ${scope} scope`,
      };
    } catch (error) {
      console.error("Error verificando permisos:", error);
      return {
        hasPermission: false,
        reason: "Error interno verificando permisos",
      };
    }
  }

  /**
   * Obtener roles efectivos de un usuario con permisos consolidados
   * @param {string} userId - ID del usuario
   */
  async getUserEffectivePermissions(userId) {
    try {
      const userRoles = await this.getUserRoles(userId);

      if (!userRoles || userRoles.length === 0) {
        return {
          roles: [],
          permissions: {},
          effectiveHierarchy: 0,
        };
      }

      // Consolidar permisos de todos los roles
      const consolidatedPermissions = {};
      let maxHierarchy = 0;

      userRoles.forEach((role) => {
        maxHierarchy = Math.max(maxHierarchy, role.hierarchy);

        role.permissions.forEach((permission) => {
          const key = permission.resource;

          if (!consolidatedPermissions[key]) {
            consolidatedPermissions[key] = {
              actions: new Set(),
              maxScope: permission.scope,
              conditions: { ...permission.conditions },
            };
          }

          // Agregar acciones
          permission.actions.forEach((action) => {
            consolidatedPermissions[key].actions.add(action);
          });

          // Usar el scope más permisivo
          const scopeHierarchy = ["none", "own", "company", "global"];
          const currentScopeLevel = scopeHierarchy.indexOf(permission.scope);
          const maxScopeLevel = scopeHierarchy.indexOf(
            consolidatedPermissions[key].maxScope
          );

          if (currentScopeLevel > maxScopeLevel) {
            consolidatedPermissions[key].maxScope = permission.scope;
          }

          // Combinar condiciones
          Object.assign(
            consolidatedPermissions[key].conditions,
            permission.conditions
          );
        });
      });

      // Convertir Sets a arrays
      Object.keys(consolidatedPermissions).forEach((resource) => {
        consolidatedPermissions[resource].actions = Array.from(
          consolidatedPermissions[resource].actions
        );
      });

      return {
        roles: userRoles.map((role) => ({
          roleId: role._id,
          roleName: role.roleName,
          displayName: role.displayName,
          hierarchy: role.hierarchy,
          category: role.metadata?.category,
        })),
        permissions: consolidatedPermissions,
        effectiveHierarchy: maxHierarchy,
        canManageAllCompanies: userRoles.some(
          (role) => role.companyRestrictions?.canManageAllCompanies
        ),
      };
    } catch (error) {
      console.error("Error obteniendo permisos efectivos:", error);
      throw new AuthError(
        "Error obteniendo permisos del usuario",
        AuthErrorCodes.PERMISSION_RETRIEVAL_FAILED,
        500
      );
    }
  }

  /**
   * Obtener roles disponibles para asignar
   * @param {string} adminUserId - ID del usuario administrador
   * @param {Object} filters - Filtros adicionales
   */
  async getAssignableRoles(adminUserId, filters = {}) {
    try {
      // Obtener jerarquía del administrador
      const adminRoles = await this.getUserRoles(adminUserId);
      const adminHierarchy = Math.max(
        ...adminRoles.map((role) => role.hierarchy),
        0
      );

      // Solo mostrar roles con jerarquía menor que la del admin
      const roleFilters = {
        ...filters,
        isActive: true,
        hierarchy: { $lt: adminHierarchy },
      };

      const roles = await this.roleRepository.findWithFilters(roleFilters, {
        sortBy: "hierarchy",
        sortOrder: -1,
      });

      // Agregar información adicional sobre disponibilidad
      const rolesWithAvailability = roles.docs.map((role) => ({
        ...role,
        isAssignable: this.canAssignRole(role, adminRoles),
        availableSlots: role.maxUsers
          ? Math.max(0, role.maxUsers - role.stats.userCount)
          : null,
        restrictions: this.getRoleRestrictionsSummary(role),
      }));

      return {
        roles: rolesWithAvailability,
        pagination: {
          totalDocs: roles.totalDocs,
          totalPages: roles.totalPages,
          page: roles.page,
          limit: roles.limit,
        },
        adminHierarchy,
      };
    } catch (error) {
      console.error("Error obteniendo roles asignables:", error);
      throw new AuthError(
        "Error obteniendo roles disponibles",
        AuthErrorCodes.ROLE_RETRIEVAL_FAILED,
        500
      );
    }
  }

  /**
   * Crear rol personalizado para empresa
   * @param {string} companyId - ID de la empresa
   * @param {Object} roleData - Datos del rol personalizado
   * @param {Object} requestInfo - Información del request
   */
  async createCompanyRole(companyId, roleData, requestInfo) {
    try {
      const { userId, ipAddress, userAgent } = requestInfo;

      // Validar que el usuario puede gestionar la empresa
      await this.validateCompanyManagement(userId, companyId);

      // Preparar datos del rol de empresa
      const companyRoleData = {
        ...roleData,
        roleName: `${companyId}_${roleData.roleName}`.toLowerCase(),
        displayName: `${roleData.displayName} (${companyId})`,
        isSystemRole: false,
        hierarchy: Math.min(roleData.hierarchy || 30, 30), // Máximo nivel 30 para roles de empresa
        companyRestrictions: {
          canManageAllCompanies: false,
          restrictedToOwnCompany: true,
          allowedCompanies: [companyId],
          maxCompaniesManaged: 1,
        },
        // Limitar permisos disponibles para roles de empresa
        permissions: this.filterCompanyPermissions(roleData.permissions || []),
      };

      const userData = {
        userId,
        ip: ipAddress,
        userAgent,
      };

      const newRole = await this.roleRepository.createRole(
        companyRoleData,
        userData
      );

      console.log(
        `✅ Rol de empresa creado: ${newRole.roleName} para empresa ${companyId}`
      );

      return {
        success: true,
        role: newRole,
        companyId,
      };
    } catch (error) {
      console.error("Error creando rol de empresa:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Error creando rol personalizado",
        AuthErrorCodes.COMPANY_ROLE_CREATION_FAILED,
        500
      );
    }
  }

  /**
   * Obtener resumen de roles del sistema
   * @param {Object} options - Opciones de filtrado
   */
  async getRolesSummary(options = {}) {
    try {
      const { includeStats = true, includeInactive = false } = options;

      const stats = await this.roleRepository.getRoleStats();

      const roles = await this.roleRepository.findWithFilters(
        { isActive: includeInactive ? undefined : true },
        { limit: 100, sortBy: "hierarchy", sortOrder: -1 }
      );

      const rolesByCategory = roles.docs.reduce((acc, role) => {
        const category = role.metadata?.category || "other";
        if (!acc[category]) {
          acc[category] = [];
        }
        acc[category].push({
          roleId: role._id,
          roleName: role.roleName,
          displayName: role.displayName,
          hierarchy: role.hierarchy,
          userCount: role.stats?.userCount || 0,
          isSystemRole: role.isSystemRole,
          isActive: role.isActive,
        });
        return acc;
      }, {});

      return {
        statistics: stats,
        rolesByCategory,
        totalRoles: roles.totalDocs,
        systemHealth: {
          hasDefaultRole: stats.general.defaultRoles > 0,
          hasAdminRoles: stats.general.systemRoles > 0,
          rolesWithUsers: stats.general.totalUsersAssigned > 0,
        },
      };
    } catch (error) {
      console.error("Error obteniendo resumen de roles:", error);
      throw new AuthError(
        "Error obteniendo resumen de roles",
        AuthErrorCodes.ROLE_SUMMARY_FAILED,
        500
      );
    }
  }

  /**
   * Migrar permisos entre roles
   * @param {string} sourceRoleId - ID del rol origen
   * @param {string} targetRoleId - ID del rol destino
   * @param {Array} permissionsToMigrate - Permisos específicos a migrar
   * @param {Object} requestInfo - Información del request
   */
  async migrateRolePermissions(
    sourceRoleId,
    targetRoleId,
    permissionsToMigrate,
    requestInfo
  ) {
    return await TransactionHelper.executeWithOptionalTransaction(
      async (session) => {
        try {
          const { userId, ipAddress, userAgent } = requestInfo;

          // Validar permisos de administrador
          await this.validateUserPermission(
            userId,
            "roles",
            "manage",
            "global"
          );

          const sourceRole = await this.roleRepository.findById(sourceRoleId);
          const targetRole = await this.roleRepository.findById(targetRoleId);

          if (!sourceRole || !targetRole) {
            throw new AuthError(
              "Rol origen o destino no encontrado",
              AuthErrorCodes.ROLE_NOT_FOUND,
              404
            );
          }

          const userData = {
            userId,
            ip: ipAddress,
            userAgent,
          };

          // Migrar permisos especificados
          for (const permissionSpec of permissionsToMigrate) {
            const { resource, actions, scope, conditions } = permissionSpec;

            // Agregar permiso al rol destino
            await this.roleRepository.addPermission(
              targetRoleId,
              resource,
              actions,
              scope,
              conditions,
              userData
            );

            // Opcionalmente, remover del rol origen
            if (permissionSpec.removeFromSource) {
              await this.roleRepository.removePermission(
                sourceRoleId,
                resource,
                null, // Remover todo el permiso para el recurso
                userData
              );
            }
          }

          console.log(
            `✅ Permisos migrados de ${sourceRole.roleName} a ${targetRole.roleName}`
          );

          return {
            success: true,
            migratedPermissions: permissionsToMigrate.length,
            sourceRole: sourceRole.roleName,
            targetRole: targetRole.roleName,
          };
        } catch (error) {
          console.error("Error migrando permisos:", error);
          if (error instanceof AuthError) {
            throw error;
          }
          throw new AuthError(
            "Error migrando permisos entre roles",
            AuthErrorCodes.PERMISSION_MIGRATION_FAILED,
            500
          );
        }
      }
    );
  }

  // =============================================================================
  // MÉTODOS AUXILIARES
  // =============================================================================

  /**
   * Obtener roles de un usuario
   * @param {string} userId - ID del usuario
   */
  async getUserRoles(userId) {
    try {
      const user = await this.userRepository.findById(userId, {
        populate: ["roles"],
      });

      return user?.roles || [];
    } catch (error) {
      console.error("Error obteniendo roles del usuario:", error);
      return [];
    }
  }

  /**
   * Validar permisos de usuario
   * @param {string} userId - ID del usuario
   * @param {string} resource - Recurso
   * @param {string} action - Acción
   * @param {string} scope - Alcance
   */
  async validateUserPermission(userId, resource, action, scope = "own") {
    const permissionCheck = await this.checkUserPermission(
      userId,
      resource,
      action,
      scope
    );

    if (!permissionCheck.hasPermission) {
      throw new AuthError(
        `Permisos insuficientes: ${permissionCheck.reason}`,
        AuthErrorCodes.PERMISSION_DENIED,
        403
      );
    }

    return permissionCheck;
  }

  /**
   * Validar datos de rol
   * @param {Object} roleData - Datos del rol
   */
  validateRoleData(roleData) {
    const errors = [];

    if (!roleData.roleName || roleData.roleName.length < 2) {
      errors.push("El nombre del rol debe tener al menos 2 caracteres");
    }

    if (!roleData.displayName || roleData.displayName.length < 2) {
      errors.push("El nombre para mostrar debe tener al menos 2 caracteres");
    }

    if (
      roleData.hierarchy !== undefined &&
      (roleData.hierarchy < 0 || roleData.hierarchy > 100)
    ) {
      errors.push("La jerarquía debe estar entre 0 y 100");
    }

    if (roleData.permissions) {
      try {
        this.validatePermissions(roleData.permissions);
      } catch (error) {
        errors.push(error.message);
      }
    }

    if (errors.length > 0) {
      throw new AuthError(
        `Datos de rol inválidos: ${errors.join(", ")}`,
        AuthErrorCodes.INVALID_ROLE_DATA,
        400
      );
    }
  }

  /**
   * Validar permisos
   * @param {Array} permissions - Lista de permisos
   */
  validatePermissions(permissions) {
    const validResources = Object.values(AuthConstants.RESOURCES);
    const validActions = Object.values(AuthConstants.ACTIONS);
    const validScopes = Object.values(AuthConstants.PERMISSION_SCOPES);

    permissions.forEach((permission, index) => {
      if (!validResources.includes(permission.resource)) {
        throw new Error(
          `Permiso ${index}: recurso '${permission.resource}' no válido`
        );
      }

      const actions = Array.isArray(permission.actions)
        ? permission.actions
        : [permission.actions];
      for (const action of actions) {
        if (!validActions.includes(action)) {
          throw new Error(`Permiso ${index}: acción '${action}' no válida`);
        }
      }

      if (!validScopes.includes(permission.scope)) {
        throw new Error(
          `Permiso ${index}: alcance '${permission.scope}' no válido`
        );
      }
    });
  }

  /**
   * Verificar si se puede asignar un rol
   * @param {Object} role - Rol a verificar
   * @param {Array} adminRoles - Roles del administrador
   */
  canAssignRole(role, adminRoles) {
    // No se pueden asignar roles con jerarquía igual o mayor
    const maxAdminHierarchy = Math.max(
      ...adminRoles.map((r) => r.hierarchy),
      0
    );
    if (role.hierarchy >= maxAdminHierarchy) {
      return false;
    }

    // Verificar si el rol está disponible
    if (role.maxUsers && role.stats.userCount >= role.maxUsers) {
      return false;
    }

    // Verificar si está expirado
    if (role.expiresAt && role.expiresAt < new Date()) {
      return false;
    }

    return true;
  }

  /**
   * Obtener resumen de restricciones de rol
   * @param {Object} role - Rol
   */
  getRoleRestrictionsSummary(role) {
    const restrictions = [];

    if (role.maxUsers) {
      restrictions.push(`Máximo ${role.maxUsers} usuarios`);
    }

    if (role.expiresAt) {
      restrictions.push(`Expira el ${role.expiresAt.toLocaleDateString()}`);
    }

    if (role.companyRestrictions?.restrictedToOwnCompany) {
      restrictions.push("Restringido a empresa propia");
    }

    if (role.geographicRestrictions?.restrictToGeolocation) {
      restrictions.push("Restricciones geográficas");
    }

    return restrictions;
  }

  /**
   * Verificar restricciones de rol
   * @param {Object} role - Rol
   * @param {Object} context - Contexto
   */
  checkRoleRestrictions(role, context = {}) {
    const errors = [];

    // Verificar expiración
    if (role.expiresAt && role.expiresAt < new Date()) {
      errors.push("Rol expirado");
    }

    // Verificar restricciones geográficas
    if (role.geographicRestrictions?.restrictToGeolocation) {
      if (context.country && role.geographicRestrictions.allowedCountries) {
        if (
          !role.geographicRestrictions.allowedCountries.includes(
            context.country
          )
        ) {
          errors.push("País no permitido");
        }
      }
    }

    // Verificar restricciones de empresa
    if (context.companyId && role.companyRestrictions?.restrictedToOwnCompany) {
      if (role.companyRestrictions.allowedCompanies) {
        if (
          !role.companyRestrictions.allowedCompanies.includes(context.companyId)
        ) {
          errors.push("Empresa no permitida");
        }
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Obtener alcance efectivo de un permiso
   * @param {Object} role - Rol
   * @param {string} resource - Recurso
   * @param {string} action - Acción
   */
  getEffectiveScope(role, resource, action) {
    const permission = role.permissions.find((p) => p.resource === resource);
    if (!permission) return "none";

    if (
      permission.actions.includes("manage") ||
      permission.actions.includes(action)
    ) {
      return permission.scope;
    }

    return "none";
  }

  /**
   * Filtrar permisos para roles de empresa
   * @param {Array} permissions - Permisos originales
   */
  filterCompanyPermissions(permissions) {
    const allowedResources = ["businesses", "reviews", "users", "reports"];
    const restrictedActions = ["delete", "manage"]; // Solo para ciertos recursos

    return permissions.filter((permission) => {
      // Solo permitir recursos específicos
      if (!allowedResources.includes(permission.resource)) {
        return false;
      }

      // Restringir acciones peligrosas
      if (permission.resource === "users") {
        const allowedActions = permission.actions.filter(
          (action) => !restrictedActions.includes(action)
        );
        permission.actions = allowedActions;
        return allowedActions.length > 0;
      }

      // Forzar scope máximo de "company" para roles de empresa
      if (permission.scope === "global") {
        permission.scope = "company";
      }

      return true;
    });
  }

  /**
   * Validar gestión de empresa
   * @param {string} userId - ID del usuario
   * @param {string} companyId - ID de la empresa
   */
  async validateCompanyManagement(userId, companyId) {
    const userRoles = await this.getUserRoles(userId);

    const canManage = userRoles.some((role) => {
      return this.roleRepository.canManageCompany(role, companyId);
    });

    if (!canManage) {
      throw new AuthError(
        "No tiene permisos para gestionar esta empresa",
        AuthErrorCodes.PERMISSION_DENIED,
        403
      );
    }

    return true;
  }
}
