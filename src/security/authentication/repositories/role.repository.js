// =============================================================================
// src/modules/authentication/repositories/role.repository.js
// =============================================================================
import { Types } from "mongoose";
import { BaseRepository } from "../../../modules/core/repositories/base.repository.js";
import { Role } from "../models/role.scheme.js";
import { TransactionHelper } from "../../../utils/transsaccion.helper.js";

export class RoleRepository extends BaseRepository {
  constructor() {
    super(Role);
  }

  /**
   * Crear rol con validaciones
   * @param {Object} roleData - Datos del rol
   * @param {Object} userData - Datos del usuario que crea
   * @param {Object} options - Opciones adicionales
   */
  async createRole(roleData, userData, options = {}) {
    return await TransactionHelper.executeWithOptionalTransaction(
      async (session) => {
        try {
          // Verificar nombre único
          const existingRole = await this.model
            .findOne({
              roleName: roleData.roleName.toLowerCase(),
            })
            .session(session);

          if (existingRole) {
            throw new Error("El nombre del rol ya existe");
          }

          // Validar jerarquía del rol padre
          if (roleData.parentRole) {
            const parentRole = await this.findById(roleData.parentRole);
            if (!parentRole) {
              throw new Error("Rol padre no encontrado");
            }

            if (roleData.hierarchy >= parentRole.hierarchy) {
              throw new Error(
                "La jerarquía debe ser menor que la del rol padre"
              );
            }
          }

          // Preparar datos del rol
          const newRoleData = {
            ...roleData,
            roleName: roleData.roleName.toLowerCase(),
            permissions: this.validatePermissions(roleData.permissions || []),
            stats: {
              userCount: 0,
              totalAssignments: 0,
            },
          };

          // Solo puede haber un rol por defecto
          if (roleData.isDefault) {
            await this.model.updateMany(
              { _id: { $ne: null } },
              { $set: { isDefault: false } },
              { session }
            );
          }

          return await this.create(newRoleData, userData, { session });
        } catch (error) {
          console.error("Error creando rol:", error);
          throw error;
        }
      }
    );
  }

  /**
   * Buscar rol por nombre
   * @param {string} roleName - Nombre del rol
   * @param {Object} options - Opciones de búsqueda
   */
  async findByName(roleName, options = {}) {
    try {
      const { includeInactive = false } = options;

      let query = this.model.findOne({
        roleName: roleName.toLowerCase(),
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      });

      if (!includeInactive) {
        query = query.where({ isActive: true });
      }

      return await query.lean();
    } catch (error) {
      console.error("Error buscando rol por nombre:", error);
      throw error;
    }
  }

  /**
   * Obtener rol por defecto
   */
  async getDefaultRole() {
    try {
      return await this.model
        .findOne({
          isDefault: true,
          isActive: true,
          $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
        })
        .lean();
    } catch (error) {
      console.error("Error obteniendo rol por defecto:", error);
      throw error;
    }
  }

  /**
   * Obtener roles del sistema
   * @param {Object} options - Opciones de filtrado
   */
  async getSystemRoles(options = {}) {
    try {
      const { includeInactive = false } = options;

      let query = this.model.find({
        isSystemRole: true,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      });

      if (!includeInactive) {
        query = query.where({ isActive: true });
      }

      return await query.sort({ hierarchy: -1 }).lean();
    } catch (error) {
      console.error("Error obteniendo roles del sistema:", error);
      throw error;
    }
  }

  /**
   * Obtener roles por jerarquía
   * @param {number} minLevel - Nivel mínimo
   * @param {number} maxLevel - Nivel máximo
   * @param {Object} options - Opciones adicionales
   */
  async findByHierarchy(minLevel = 0, maxLevel = 100, options = {}) {
    try {
      const { includeInactive = false } = options;

      let query = this.model.find({
        hierarchy: { $gte: minLevel, $lte: maxLevel },
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      });

      if (!includeInactive) {
        query = query.where({ isActive: true });
      }

      return await query.sort({ hierarchy: -1 }).lean();
    } catch (error) {
      console.error("Error buscando roles por jerarquía:", error);
      throw error;
    }
  }

  /**
   * Agregar permiso a rol
   * @param {string} roleId - ID del rol
   * @param {string} resource - Recurso
   * @param {Array} actions - Acciones permitidas
   * @param {string} scope - Alcance del permiso
   * @param {Object} conditions - Condiciones adicionales
   * @param {Object} userData - Datos del usuario
   */
  async addPermission(
    roleId,
    resource,
    actions,
    scope = "own",
    conditions = {},
    userData
  ) {
    try {
      const role = await this.findById(roleId);
      if (!role) {
        throw new Error("Rol no encontrado");
      }

      // Verificar si ya existe permiso para este recurso
      const existingPermissionIndex = role.permissions.findIndex(
        (p) => p.resource === resource
      );

      const permission = {
        resource,
        actions: Array.isArray(actions) ? actions : [actions],
        scope,
        conditions,
      };

      let updateData;
      if (existingPermissionIndex >= 0) {
        // Actualizar permiso existente
        updateData = {
          [`permissions.${existingPermissionIndex}`]: permission,
        };
      } else {
        // Agregar nuevo permiso
        updateData = {
          $push: { permissions: permission },
        };
      }

      return await this.update(roleId, updateData, userData);
    } catch (error) {
      console.error("Error agregando permiso:", error);
      throw error;
    }
  }

  /**
   * Remover permiso de rol
   * @param {string} roleId - ID del rol
   * @param {string} resource - Recurso
   * @param {string} action - Acción específica (opcional)
   * @param {Object} userData - Datos del usuario
   */
  async removePermission(roleId, resource, action = null, userData) {
    try {
      const role = await this.findById(roleId);
      if (!role) {
        throw new Error("Rol no encontrado");
      }

      let updateData;

      if (action) {
        // Remover acción específica
        const permission = role.permissions.find(
          (p) => p.resource === resource
        );
        if (permission) {
          const updatedActions = permission.actions.filter((a) => a !== action);

          if (updatedActions.length === 0) {
            // Si no quedan acciones, remover el permiso completo
            updateData = {
              $pull: { permissions: { resource } },
            };
          } else {
            // Actualizar acciones
            const permissionIndex = role.permissions.findIndex(
              (p) => p.resource === resource
            );
            updateData = {
              [`permissions.${permissionIndex}.actions`]: updatedActions,
            };
          }
        }
      } else {
        // Remover todo el permiso para el recurso
        updateData = {
          $pull: { permissions: { resource } },
        };
      }

      if (updateData) {
        return await this.update(roleId, updateData, userData);
      }

      return role;
    } catch (error) {
      console.error("Error removiendo permiso:", error);
      throw error;
    }
  }

  /**
   * Verificar si un rol tiene un permiso específico
   * @param {string} roleId - ID del rol
   * @param {string} resource - Recurso
   * @param {string} action - Acción
   * @param {string} scope - Alcance requerido
   */
  async hasPermission(roleId, resource, action, scope = "own") {
    try {
      const role = await this.findById(roleId);
      if (!role || !role.isActive || this.isRoleExpired(role)) {
        return false;
      }

      // Buscar el permiso para el recurso
      const permission = role.permissions.find((p) => p.resource === resource);
      if (!permission) {
        return false;
      }

      // Verificar si tiene la acción específica o 'manage'
      const hasAction =
        permission.actions.includes(action) ||
        permission.actions.includes("manage");

      if (!hasAction) {
        return false;
      }

      // Verificar el alcance
      const scopeHierarchy = ["none", "own", "company", "global"];
      const requiredScopeLevel = scopeHierarchy.indexOf(scope);
      const permissionScopeLevel = scopeHierarchy.indexOf(permission.scope);

      return permissionScopeLevel >= requiredScopeLevel;
    } catch (error) {
      console.error("Error verificando permiso:", error);
      return false;
    }
  }

  /**
   * Obtener resumen de permisos de un rol
   * @param {string} roleId - ID del rol
   */
  async getPermissionsSummary(roleId) {
    try {
      const role = await this.findById(roleId);
      if (!role) {
        throw new Error("Rol no encontrado");
      }

      const summary = {
        roleName: role.roleName,
        displayName: role.displayName,
        hierarchy: role.hierarchy,
        totalPermissions: role.permissions.length,
        resourcesWithFullAccess: [],
        resourcesWithLimitedAccess: [],
        scopeDistribution: { none: 0, own: 0, company: 0, global: 0 },
        permissionsByResource: {},
      };

      role.permissions.forEach((permission) => {
        // Verificar si tiene acceso completo (manage)
        if (permission.actions.includes("manage")) {
          summary.resourcesWithFullAccess.push(permission.resource);
        } else {
          summary.resourcesWithLimitedAccess.push({
            resource: permission.resource,
            actions: permission.actions,
          });
        }

        // Contar distribución de alcances
        summary.scopeDistribution[permission.scope]++;

        // Agrupar por recurso
        summary.permissionsByResource[permission.resource] = {
          actions: permission.actions,
          scope: permission.scope,
          conditions: permission.conditions,
        };
      });

      return summary;
    } catch (error) {
      console.error("Error obteniendo resumen de permisos:", error);
      throw error;
    }
  }

  /**
   * Asignar rol a usuario
   * @param {string} userId - ID del usuario
   * @param {string} roleId - ID del rol
   * @param {Object} userData - Datos del usuario que asigna
   */
  async assignRole(userId, roleId, userData) {
    return await TransactionHelper.executeWithOptionalTransaction(
      async (session) => {
        try {
          const role = await this.findById(roleId);
          if (!role) {
            throw new Error("Rol no encontrado");
          }

          if (!role.isActive || this.isRoleExpired(role)) {
            throw new Error("Rol inactivo o expirado");
          }

          // Verificar límite de usuarios
          if (role.maxUsers && role.stats.userCount >= role.maxUsers) {
            throw new Error("Rol ha alcanzado el límite máximo de usuarios");
          }

          // Agregar rol al usuario (esto sería en UserRepository)
          const User = require("../models/user.scheme.js").User;
          await User.updateOne(
            { _id: userId },
            { $addToSet: { roles: roleId } },
            { session }
          );

          // Actualizar estadísticas del rol
          await this.model.updateOne(
            { _id: roleId },
            {
              $inc: {
                "stats.userCount": 1,
                "stats.totalAssignments": 1,
              },
              $set: { "stats.lastAssigned": new Date() },
            },
            { session }
          );

          console.log(`✅ Rol ${role.roleName} asignado a usuario ${userId}`);
          return true;
        } catch (error) {
          console.error("Error asignando rol:", error);
          throw error;
        }
      }
    );
  }

  /**
   * Remover rol de usuario
   * @param {string} userId - ID del usuario
   * @param {string} roleId - ID del rol
   * @param {Object} userData - Datos del usuario que remueve
   */
  async removeRole(userId, roleId, userData) {
    return await TransactionHelper.executeWithOptionalTransaction(
      async (session) => {
        try {
          // Remover rol del usuario
          const User = require("../models/user.scheme.js").User;
          await User.updateOne(
            { _id: userId },
            { $pull: { roles: roleId } },
            { session }
          );

          // Actualizar estadísticas del rol
          await this.model.updateOne(
            { _id: roleId },
            { $inc: { "stats.userCount": -1 } },
            { session }
          );

          console.log(`✅ Rol removido de usuario ${userId}`);
          return true;
        } catch (error) {
          console.error("Error removiendo rol:", error);
          throw error;
        }
      }
    );
  }

  /**
   * Actualizar estadísticas de rol
   * @param {string} roleId - ID del rol
   */
  async updateRoleStats(roleId) {
    try {
      const User = require("../models/user.scheme.js").User;

      const userCount = await User.countDocuments({
        roles: roleId,
        isActive: true,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      });

      await this.model.updateOne(
        { _id: roleId },
        {
          "stats.userCount": userCount,
          "stats.lastAssigned": new Date(),
        }
      );

      return userCount;
    } catch (error) {
      console.error("Error actualizando estadísticas de rol:", error);
      throw error;
    }
  }

  /**
   * Buscar roles con filtros avanzados
   * @param {Object} filters - Filtros de búsqueda
   * @param {Object} options - Opciones de paginación
   */
  async findWithFilters(filters = {}, options = {}) {
    try {
      const {
        search,
        category,
        hierarchy,
        isSystemRole,
        isActive,
        hasUsers,
        permissions,
      } = filters;

      const {
        page = 1,
        limit = 10,
        sortBy = "hierarchy",
        sortOrder = -1,
      } = options;

      let query = {
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      };

      // Filtro por búsqueda de texto
      if (search) {
        query.$and = query.$and || [];
        query.$and.push({
          $or: [
            { roleName: { $regex: search, $options: "i" } },
            { displayName: { $regex: search, $options: "i" } },
            { description: { $regex: search, $options: "i" } },
          ],
        });
      }

      // Filtros específicos
      if (category) query["metadata.category"] = category;
      if (hierarchy !== undefined) {
        if (typeof hierarchy === "object") {
          query.hierarchy = hierarchy; // { $gte: 50, $lte: 100 }
        } else {
          query.hierarchy = hierarchy;
        }
      }
      if (isSystemRole !== undefined) query.isSystemRole = isSystemRole;
      if (isActive !== undefined) query.isActive = isActive;

      // Filtro por roles con usuarios
      if (hasUsers !== undefined) {
        if (hasUsers) {
          query["stats.userCount"] = { $gt: 0 };
        } else {
          query["stats.userCount"] = 0;
        }
      }

      // Filtro por permisos específicos
      if (permissions && permissions.length > 0) {
        query.$and = query.$and || [];
        permissions.forEach((permission) => {
          if (permission.resource) {
            const permissionQuery = {
              "permissions.resource": permission.resource,
            };
            if (permission.action) {
              permissionQuery["permissions.actions"] = permission.action;
            }
            query.$and.push(permissionQuery);
          }
        });
      }

      return await this.findAll(query, {
        page,
        limit,
        sort: { [sortBy]: sortOrder },
      });
    } catch (error) {
      console.error("Error buscando roles con filtros:", error);
      throw error;
    }
  }

  /**
   * Crear roles predeterminados del sistema
   */
  async createSystemRoles() {
    try {
      const systemRoles = [
        {
          roleName: "super_admin",
          displayName: "Super Administrador",
          description: "Acceso completo al sistema",
          hierarchy: 100,
          isSystemRole: true,
          permissions: [
            { resource: "users", actions: ["manage"], scope: "global" },
            { resource: "businesses", actions: ["manage"], scope: "global" },
            { resource: "reviews", actions: ["manage"], scope: "global" },
            { resource: "categories", actions: ["manage"], scope: "global" },
            { resource: "roles", actions: ["manage"], scope: "global" },
            { resource: "system", actions: ["manage"], scope: "global" },
            { resource: "reports", actions: ["manage"], scope: "global" },
            { resource: "audit", actions: ["manage"], scope: "global" },
          ],
          companyRestrictions: {
            canManageAllCompanies: true,
            restrictedToOwnCompany: false,
          },
          metadata: {
            color: "#FF0000",
            icon: "crown",
            category: "admin",
            priority: 10,
          },
        },
        {
          roleName: "admin",
          displayName: "Administrador",
          description: "Administrador del sistema con acceso limitado",
          hierarchy: 80,
          isSystemRole: true,
          permissions: [
            {
              resource: "users",
              actions: ["create", "read", "update"],
              scope: "global",
            },
            { resource: "businesses", actions: ["manage"], scope: "global" },
            { resource: "reviews", actions: ["manage"], scope: "global" },
            { resource: "categories", actions: ["manage"], scope: "global" },
            {
              resource: "reports",
              actions: ["read", "export"],
              scope: "global",
            },
          ],
          companyRestrictions: {
            canManageAllCompanies: true,
            restrictedToOwnCompany: false,
          },
          metadata: {
            color: "#FF6600",
            icon: "shield",
            category: "admin",
            priority: 8,
          },
        },
        {
          roleName: "business_owner",
          displayName: "Propietario de Empresa",
          description: "Propietario que puede gestionar su empresa",
          hierarchy: 50,
          isSystemRole: true,
          permissions: [
            {
              resource: "businesses",
              actions: ["read", "update"],
              scope: "own",
            },
            {
              resource: "reviews",
              actions: ["read", "approve", "reject"],
              scope: "company",
            },
            { resource: "users", actions: ["read"], scope: "company" },
            { resource: "reports", actions: ["read"], scope: "company" },
          ],
          companyRestrictions: {
            canManageAllCompanies: false,
            restrictedToOwnCompany: true,
            maxCompaniesManaged: 5,
          },
          metadata: {
            color: "#0066FF",
            icon: "building",
            category: "business",
            priority: 5,
          },
        },
        {
          roleName: "customer",
          displayName: "Cliente",
          description: "Usuario cliente con permisos básicos",
          hierarchy: 10,
          isSystemRole: true,
          isDefault: true,
          permissions: [
            { resource: "businesses", actions: ["read"], scope: "global" },
            {
              resource: "reviews",
              actions: ["create", "read", "update"],
              scope: "own",
            },
            { resource: "users", actions: ["read", "update"], scope: "own" },
          ],
          companyRestrictions: {
            canManageAllCompanies: false,
            restrictedToOwnCompany: true,
            maxCompaniesManaged: 0,
          },
          metadata: {
            color: "#00CC66",
            icon: "user",
            category: "customer",
            priority: 1,
          },
        },
      ];

      const createdRoles = [];

      for (const roleData of systemRoles) {
        try {
          const existingRole = await this.findByName(roleData.roleName);

          if (!existingRole) {
            // Crear datos de usuario del sistema para auditoría
            const systemUserData = {
              userId: null, // Usuario del sistema
              ip: "127.0.0.1",
              userAgent: "System",
            };

            const role = await this.createRole(roleData, systemUserData);
            createdRoles.push(role);
            console.log(`✅ Rol del sistema creado: ${roleData.displayName}`);
          } else {
            console.log(
              `ℹ️  Rol del sistema ya existe: ${roleData.displayName}`
            );
          }
        } catch (error) {
          console.error(
            `❌ Error creando rol ${roleData.roleName}:`,
            error.message
          );
        }
      }

      return createdRoles;
    } catch (error) {
      console.error("Error creando roles del sistema:", error);
      throw error;
    }
  }

  /**
   * Obtener estadísticas de roles
   */
  async getRoleStats() {
    try {
      const stats = await this.model.aggregate([
        {
          $match: {
            $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
          },
        },
        {
          $group: {
            _id: null,
            totalRoles: { $sum: 1 },
            activeRoles: {
              $sum: { $cond: [{ $eq: ["$isActive", true] }, 1, 0] },
            },
            systemRoles: {
              $sum: { $cond: [{ $eq: ["$isSystemRole", true] }, 1, 0] },
            },
            defaultRoles: {
              $sum: { $cond: [{ $eq: ["$isDefault", true] }, 1, 0] },
            },
            totalUsersAssigned: { $sum: "$stats.userCount" },
            avgHierarchy: { $avg: "$hierarchy" },
            totalPermissions: { $sum: { $size: "$permissions" } },
          },
        },
      ]);

      // Estadísticas por categoría
      const categoryStats = await this.model.aggregate([
        {
          $match: {
            isActive: true,
            $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
          },
        },
        {
          $group: {
            _id: "$metadata.category",
            count: { $sum: 1 },
            avgHierarchy: { $avg: "$hierarchy" },
            totalUsers: { $sum: "$stats.userCount" },
          },
        },
        { $sort: { count: -1 } },
      ]);

      // Estadísticas por nivel de jerarquía
      const hierarchyStats = await this.model.aggregate([
        {
          $match: {
            isActive: true,
            $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
          },
        },
        {
          $bucket: {
            groupBy: "$hierarchy",
            boundaries: [0, 25, 50, 75, 101],
            default: "Other",
            output: {
              count: { $sum: 1 },
              roles: { $push: "$roleName" },
              totalUsers: { $sum: "$stats.userCount" },
            },
          },
        },
      ]);

      return {
        general: stats[0] || {
          totalRoles: 0,
          activeRoles: 0,
          systemRoles: 0,
          defaultRoles: 0,
          totalUsersAssigned: 0,
          avgHierarchy: 0,
          totalPermissions: 0,
        },
        byCategory: categoryStats,
        byHierarchy: hierarchyStats,
      };
    } catch (error) {
      console.error("Error obteniendo estadísticas de roles:", error);
      throw error;
    }
  }

  /**
   * Exportar configuración de roles
   * @param {Object} options - Opciones de exportación
   */
  async exportRoleConfiguration(options = {}) {
    try {
      const { includeSystemRoles = true, includeStats = false } = options;

      let query = {
        isActive: true,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      };

      if (!includeSystemRoles) {
        query.isSystemRole = false;
      }

      const roles = await this.model.find(query).lean();

      const exportData = roles.map((role) => {
        const exported = {
          roleName: role.roleName,
          displayName: role.displayName,
          description: role.description,
          hierarchy: role.hierarchy,
          permissions: role.permissions,
          isSystemRole: role.isSystemRole,
          isDefault: role.isDefault,
          metadata: role.metadata,
          companyRestrictions: role.companyRestrictions,
          geographicRestrictions: role.geographicRestrictions,
        };

        if (includeStats) {
          exported.stats = role.stats;
        }

        return exported;
      });

      return {
        exportDate: new Date(),
        totalRoles: exportData.length,
        roles: exportData,
      };
    } catch (error) {
      console.error("Error exportando configuración de roles:", error);
      throw error;
    }
  }

  // =============================================================================
  // MÉTODOS AUXILIARES
  // =============================================================================

  /**
   * Validar permisos
   * @param {Array} permissions - Lista de permisos
   */
  validatePermissions(permissions) {
    const validResources = [
      "users",
      "businesses",
      "reviews",
      "categories",
      "addresses",
      "roles",
      "permissions",
      "system",
      "reports",
      "audit",
      "translations",
      "media",
      "notifications",
      "analytics",
    ];

    const validActions = [
      "create",
      "read",
      "update",
      "delete",
      "manage",
      "approve",
      "reject",
      "publish",
      "unpublish",
      "export",
      "import",
      "restore",
      "archive",
    ];

    const validScopes = ["global", "company", "own", "none"];

    return permissions.map((permission) => {
      // Validar recurso
      if (!validResources.includes(permission.resource)) {
        throw new Error(`Recurso inválido: ${permission.resource}`);
      }

      // Validar acciones
      const actions = Array.isArray(permission.actions)
        ? permission.actions
        : [permission.actions];
      for (const action of actions) {
        if (!validActions.includes(action)) {
          throw new Error(`Acción inválida: ${action}`);
        }
      }

      // Validar alcance
      if (!validScopes.includes(permission.scope)) {
        throw new Error(`Alcance inválido: ${permission.scope}`);
      }

      return {
        resource: permission.resource,
        actions: actions,
        scope: permission.scope || "own",
        conditions: permission.conditions || {},
      };
    });
  }

  /**
   * Verificar si un rol está expirado
   * @param {Object} role - Objeto del rol
   */
  isRoleExpired(role) {
    return role.expiresAt && role.expiresAt < new Date();
  }

  /**
   * Verificar si un rol puede gestionar empresa
   * @param {Object} role - Objeto del rol
   * @param {string} companyId - ID de la empresa (opcional)
   */
  canManageCompany(role, companyId = null) {
    if (!role.isActive || this.isRoleExpired(role)) {
      return false;
    }

    const restrictions = role.companyRestrictions || {};

    if (restrictions.canManageAllCompanies) {
      return true;
    }

    if (
      companyId &&
      restrictions.allowedCompanies &&
      restrictions.allowedCompanies.length > 0
    ) {
      return restrictions.allowedCompanies.some((id) =>
        id.equals ? id.equals(companyId) : id === companyId
      );
    }

    return !restrictions.restrictedToOwnCompany;
  }

  /**
   * Verificar restricciones geográficas
   * @param {Object} role - Objeto del rol
   * @param {string} country - País (opcional)
   * @param {string} region - Región (opcional)
   */
  checkGeographicRestrictions(role, country = null, region = null) {
    const restrictions = role.geographicRestrictions || {};

    if (!restrictions.restrictToGeolocation) {
      return true;
    }

    // Verificar país
    if (
      country &&
      restrictions.allowedCountries &&
      restrictions.allowedCountries.length > 0
    ) {
      if (!restrictions.allowedCountries.includes(country.toUpperCase())) {
        return false;
      }
    }

    // Verificar región
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
  }
}
