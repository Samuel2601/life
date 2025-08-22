// =============================================================================
// src/modules/authentication/repositories/role.repository.js - VERSIÓN COMPLETA UNIFICADA
// Utiliza al 100% las funcionalidades del Role Schema optimizado + BaseRepository mejorado
// =============================================================================
import { Types } from "mongoose";
import { BaseRepository } from "../../../modules/core/repositories/base.repository.js";
import { Role } from "../models/role.scheme.js";
import { TransactionHelper } from "../../../utils/transsaccion.helper.js";

export class RoleRepository extends BaseRepository {
  constructor() {
    super(Role);
  }

  // ===== MÉTODOS PRINCIPALES DE GESTIÓN DE ROLES =====

  /**
   * Crear rol con validaciones completas y configuración avanzada
   * @param {Object} roleData - Datos del rol
   * @param {Object} userData - Datos del usuario que crea
   * @param {Object} options - Opciones adicionales
   */
  async createRole(roleData, userData, options = {}) {
    return await TransactionHelper.executeWithOptionalTransaction(
      async (session) => {
        try {
          // Verificar si el rol ya existe
          const existingRole = await this.model
            .findOne({
              roleName: roleData.roleName.toLowerCase(),
            })
            .session(session);

          if (existingRole) {
            throw new Error("El nombre del rol ya existe");
          }

          // Validar rol padre si se especifica
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

          // Preparar datos del nuevo rol con configuraciones por defecto
          const newRoleData = {
            ...roleData,
            roleName: roleData.roleName.toLowerCase(),
            permissions: this.validatePermissions(roleData.permissions || []),

            // Configuración de sesión por defecto
            sessionConfig: {
              maxConcurrentSessions:
                roleData.sessionConfig?.maxConcurrentSessions || 3,
              sessionTimeoutMinutes:
                roleData.sessionConfig?.sessionTimeoutMinutes || 480,
              requireTwoFactor:
                roleData.sessionConfig?.requireTwoFactor || false,
              allowRememberMe:
                roleData.sessionConfig?.allowRememberMe !== false,
            },

            // Configuración de notificaciones por defecto
            notificationSettings: {
              enableSystemNotifications:
                roleData.notificationSettings?.enableSystemNotifications !==
                false,
              enableBusinessNotifications:
                roleData.notificationSettings?.enableBusinessNotifications !==
                false,
              notificationChannels: roleData.notificationSettings
                ?.notificationChannels || ["email", "in_app"],
              dailyDigest: roleData.notificationSettings?.dailyDigest || false,
            },

            // Estadísticas iniciales
            stats: {
              userCount: 0,
              totalAssignments: 0,
              avgSessionDuration: 0,
              lastUsed: null,
            },

            // Restricciones geográficas por defecto
            geographicRestrictions: {
              allowedCountries:
                roleData.geographicRestrictions?.allowedCountries || [],
              allowedRegions:
                roleData.geographicRestrictions?.allowedRegions || [],
              restrictToGeolocation:
                roleData.geographicRestrictions?.restrictToGeolocation || false,
            },
          };

          // Si es rol por defecto, desactivar otros roles por defecto
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
   * Actualizar rol con validaciones
   * @param {string} roleId - ID del rol
   * @param {Object} updateData - Datos a actualizar
   * @param {Object} userData - Datos del usuario
   */
  async updateRole(roleId, updateData, userData) {
    try {
      const role = await this.findById(roleId);
      if (!role) {
        throw new Error("Rol no encontrado");
      }

      // Validar permisos si se actualizan
      if (updateData.permissions) {
        updateData.permissions = this.validatePermissions(
          updateData.permissions
        );
      }

      // Normalizar nombre de rol si se actualiza
      if (updateData.roleName) {
        updateData.roleName = updateData.roleName.toLowerCase();

        // Verificar que no exista otro rol con el mismo nombre
        const existingRole = await this.model.findOne({
          roleName: updateData.roleName,
          _id: { $ne: roleId },
        });

        if (existingRole) {
          throw new Error("Ya existe otro rol con ese nombre");
        }
      }

      // Si se marca como default, desactivar otros
      if (updateData.isDefault) {
        await this.model.updateMany(
          { _id: { $ne: roleId } },
          { $set: { isDefault: false } }
        );
      }

      return await this.update(roleId, updateData, userData);
    } catch (error) {
      console.error("Error actualizando rol:", error);
      throw error;
    }
  }

  // ===== CONFIGURACIONES ESPECÍFICAS DE ROL =====

  /**
   * Configurar sesión específica de rol
   * @param {string} roleId - ID del rol
   * @param {Object} sessionConfig - Configuración de sesión
   * @param {Object} userData - Datos del usuario
   */
  async updateSessionConfig(roleId, sessionConfig, userData) {
    try {
      const role = await this.findById(roleId);
      if (!role) {
        throw new Error("Rol no encontrado");
      }

      const validSessionConfig = {
        maxConcurrentSessions: Math.min(
          Math.max(sessionConfig.maxConcurrentSessions || 3, 1),
          10
        ),
        sessionTimeoutMinutes: Math.min(
          Math.max(sessionConfig.sessionTimeoutMinutes || 480, 15),
          43200 // 30 días
        ),
        requireTwoFactor: Boolean(sessionConfig.requireTwoFactor),
        allowRememberMe: Boolean(sessionConfig.allowRememberMe),
      };

      return await this.update(
        roleId,
        { sessionConfig: validSessionConfig },
        userData
      );
    } catch (error) {
      console.error("Error actualizando configuración de sesión:", error);
      throw error;
    }
  }

  /**
   * Configurar notificaciones de rol
   * @param {string} roleId - ID del rol
   * @param {Object} notificationSettings - Configuración de notificaciones
   * @param {Object} userData - Datos del usuario
   */
  async updateNotificationSettings(roleId, notificationSettings, userData) {
    try {
      const role = await this.findById(roleId);
      if (!role) {
        throw new Error("Rol no encontrado");
      }

      const validChannels = ["email", "sms", "push", "in_app"];
      const filteredChannels = (
        notificationSettings.notificationChannels || []
      ).filter((channel) => validChannels.includes(channel));

      const validNotificationSettings = {
        enableSystemNotifications: Boolean(
          notificationSettings.enableSystemNotifications
        ),
        enableBusinessNotifications: Boolean(
          notificationSettings.enableBusinessNotifications
        ),
        notificationChannels: filteredChannels,
        dailyDigest: Boolean(notificationSettings.dailyDigest),
      };

      return await this.update(
        roleId,
        { notificationSettings: validNotificationSettings },
        userData
      );
    } catch (error) {
      console.error(
        "Error actualizando configuración de notificaciones:",
        error
      );
      throw error;
    }
  }

  /**
   * Configurar restricciones geográficas
   * @param {string} roleId - ID del rol
   * @param {Object} restrictions - Restricciones geográficas
   * @param {Object} userData - Datos del usuario
   */
  async updateGeographicRestrictions(roleId, restrictions, userData) {
    try {
      const role = await this.findById(roleId);
      if (!role) {
        throw new Error("Rol no encontrado");
      }

      // Validar códigos de país ISO
      const validCountryCodes =
        restrictions.allowedCountries
          ?.filter((code) => /^[A-Z]{2}$/.test(code.toUpperCase()))
          .map((code) => code.toUpperCase()) || [];

      const validRestrictions = {
        allowedCountries: validCountryCodes,
        allowedRegions: restrictions.allowedRegions || [],
        restrictToGeolocation: Boolean(restrictions.restrictToGeolocation),
      };

      return await this.update(
        roleId,
        { geographicRestrictions: validRestrictions },
        userData
      );
    } catch (error) {
      console.error("Error actualizando restricciones geográficas:", error);
      throw error;
    }
  }

  // ===== GESTIÓN DE PERMISOS AVANZADA =====

  /**
   * Agregar permiso con restricciones de tiempo y ubicación
   * @param {string} roleId - ID del rol
   * @param {Object} permission - Permiso a agregar
   * @param {Object} userData - Datos del usuario
   */
  async addTimeRestrictedPermission(roleId, permission, userData) {
    try {
      const role = await this.findById(roleId);
      if (!role) {
        throw new Error("Rol no encontrado");
      }

      const timeRestrictedPermission = {
        ...permission,
        timeRestrictions: {
          businessHoursOnly: Boolean(
            permission.timeRestrictions?.businessHoursOnly
          ),
          timezone: permission.timeRestrictions?.timezone || "America/Lima",
          allowedDays: permission.timeRestrictions?.allowedDays || [
            1, 2, 3, 4, 5,
          ], // Lun-Vie
          allowedHours: {
            start: permission.timeRestrictions?.allowedHours?.start || "08:00",
            end: permission.timeRestrictions?.allowedHours?.end || "18:00",
          },
        },
        geographicRestrictions: {
          allowedCountries:
            permission.geographicRestrictions?.allowedCountries || [],
          allowedRegions:
            permission.geographicRestrictions?.allowedRegions || [],
          restrictToLocation: Boolean(
            permission.geographicRestrictions?.restrictToLocation
          ),
        },
      };

      const currentPermissions = role.permissions || [];
      const existingIndex = currentPermissions.findIndex(
        (p) => p.resource === permission.resource
      );

      if (existingIndex >= 0) {
        currentPermissions[existingIndex] = timeRestrictedPermission;
      } else {
        currentPermissions.push(timeRestrictedPermission);
      }

      return await this.update(
        roleId,
        { permissions: currentPermissions },
        userData
      );
    } catch (error) {
      console.error(
        "Error agregando permiso con restricción de tiempo:",
        error
      );
      throw error;
    }
  }

  /**
   * Agregar permiso simple a rol
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
        geographicRestrictions: {
          restrictToLocation: false,
        },
        timeRestrictions: {
          businessHoursOnly: false,
        },
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
   * Validar permiso con contexto completo (tiempo, ubicación, etc.)
   * @param {string} roleId - ID del rol
   * @param {string} resource - Recurso
   * @param {string} action - Acción
   * @param {Object} context - Contexto de validación
   */
  async validatePermissionWithContext(roleId, resource, action, context = {}) {
    try {
      const role = await this.findById(roleId);
      if (!role || !role.isActive) {
        return { hasPermission: false, reason: "Rol inactivo o no encontrado" };
      }

      // Verificar si el rol ha expirado
      if (role.expiresAt && role.expiresAt < new Date()) {
        return { hasPermission: false, reason: "Rol expirado" };
      }

      const permission = role.permissions.find(
        (p) => p.resource === resource || p.resource === "all"
      );
      if (!permission) {
        return { hasPermission: false, reason: "Permiso no encontrado" };
      }

      const hasAction =
        permission.actions.includes(action) ||
        permission.actions.includes("manage") ||
        permission.actions.includes("all");

      if (!hasAction) {
        return { hasPermission: false, reason: "Acción no permitida" };
      }

      // Validar restricciones geográficas
      if (
        context.location &&
        role.geographicRestrictions?.restrictToGeolocation
      ) {
        const geoValid = this.validateGeographicRestrictions(
          role,
          context.location
        );
        if (!geoValid) {
          return {
            hasPermission: false,
            reason: "Ubicación geográfica no permitida",
          };
        }
      }

      // Validar restricciones de tiempo
      if (permission.timeRestrictions?.businessHoursOnly) {
        const timeValid = this.validateTimeRestrictions(
          permission.timeRestrictions,
          context.currentTime
        );
        if (!timeValid) {
          return {
            hasPermission: false,
            reason: "Fuera del horario permitido",
          };
        }
      }

      return {
        hasPermission: true,
        permission,
        sessionConfig: role.sessionConfig,
        notificationSettings: role.notificationSettings,
      };
    } catch (error) {
      console.error("Error validando permiso con contexto:", error);
      return { hasPermission: false, reason: "Error interno" };
    }
  }

  /**
   * Verificar permiso simple (compatibilidad hacia atrás)
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
      const permission = role.permissions.find(
        (p) => p.resource === resource || p.resource === "all"
      );
      if (!permission) {
        return false;
      }

      // Verificar si tiene la acción específica o 'manage'
      const hasAction =
        permission.actions.includes(action) ||
        permission.actions.includes("manage") ||
        permission.actions.includes("all");

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

  // ===== BÚSQUEDAS Y CONSULTAS AVANZADAS =====

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
   * Buscar roles con agregación avanzada usando BaseRepository
   * @param {Object} filters - Filtros de búsqueda
   * @param {Object} options - Opciones de paginación
   */
  async findRolesWithAggregation(filters = {}, options = {}) {
    try {
      const {
        search,
        hasUsers,
        geographicRestriction,
        sessionRequirements,
        permissionResource,
        categoryFilter,
        hierarchyRange,
      } = filters;

      const searchConfig = {
        filters: {
          // Filtros básicos
          ...(search && {
            $or: [
              { roleName: { $regex: search, $options: "i" } },
              {
                "displayName.original.text": { $regex: search, $options: "i" },
              },
              {
                "description.original.text": { $regex: search, $options: "i" },
              },
            ],
          }),
          ...(categoryFilter && { "metadata.category": categoryFilter }),
          ...(hierarchyRange && {
            hierarchy: {
              $gte: hierarchyRange.min || 0,
              $lte: hierarchyRange.max || 100,
            },
          }),
        },
        options,
        lookups: [
          // Lookup con usuarios para estadísticas
          {
            from: "users",
            let: { roleId: "$_id" },
            pipeline: [
              {
                $match: {
                  $expr: { $in: ["$$roleId", "$roles"] },
                  isActive: true,
                },
              },
              { $count: "userCount" },
            ],
            as: "activeUsers",
          },
        ],
        customPipeline: [
          // Agregar conteo de usuarios activos
          {
            $addFields: {
              activeUserCount: {
                $ifNull: [{ $arrayElemAt: ["$activeUsers.userCount", 0] }, 0],
              },
            },
          },
          // Filtrar por usuarios activos si se requiere
          ...(hasUsers !== undefined
            ? [
                {
                  $match: hasUsers
                    ? { activeUserCount: { $gt: 0 } }
                    : { activeUserCount: 0 },
                },
              ]
            : []),
          // Filtrar por restricciones geográficas
          ...(geographicRestriction
            ? [
                {
                  $match: {
                    $or: [
                      { "geographicRestrictions.restrictToGeolocation": false },
                      {
                        "geographicRestrictions.allowedCountries":
                          geographicRestriction,
                      },
                    ],
                  },
                },
              ]
            : []),
          // Filtrar por requerimientos de sesión
          ...(sessionRequirements?.requireTwoFactor !== undefined
            ? [
                {
                  $match: {
                    "sessionConfig.requireTwoFactor":
                      sessionRequirements.requireTwoFactor,
                  },
                },
              ]
            : []),
          // Filtrar por recurso de permiso
          ...(permissionResource
            ? [
                {
                  $match: {
                    $or: [
                      { "permissions.resource": permissionResource },
                      { "permissions.resource": "all" },
                    ],
                  },
                },
              ]
            : []),
        ],
      };

      return await this.searchWithAggregation(searchConfig);
    } catch (error) {
      console.error("Error en búsqueda de roles con agregación:", error);
      throw error;
    }
  }

  /**
   * Buscar roles con filtros avanzados (método heredado mejorado)
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
        roleType,
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
            { "displayName.original.text": { $regex: search, $options: "i" } },
            { "description.original.text": { $regex: search, $options: "i" } },
          ],
        });
      }

      // Filtros específicos
      if (category) query["metadata.category"] = category;
      if (roleType) query.roleType = roleType;
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

  // ===== GESTIÓN DE USUARIOS Y ROLES =====

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

  // ===== ANÁLISIS Y MÉTRICAS =====

  /**
   * Análisis de uso de roles con métricas avanzadas
   * @param {string} roleId - ID del rol (opcional)
   * @param {Object} options - Opciones de análisis
   */
  async getRoleUsageAnalytics(roleId = null, options = {}) {
    try {
      const { dateFrom, dateTo } = options;

      const matchStage = roleId ? { _id: new Types.ObjectId(roleId) } : {};

      const pipeline = [
        { $match: matchStage },
        // Lookup con usuarios
        {
          $lookup: {
            from: "users",
            let: { roleId: "$_id" },
            pipeline: [
              { $match: { $expr: { $in: ["$$roleId", "$roles"] } } },
              {
                $group: {
                  _id: null,
                  totalUsers: { $sum: 1 },
                  activeUsers: {
                    $sum: { $cond: [{ $eq: ["$isActive", true] }, 1, 0] },
                  },
                  verifiedUsers: {
                    $sum: {
                      $cond: [{ $eq: ["$isEmailVerified", true] }, 1, 0],
                    },
                  },
                  avgLastLogin: { $avg: "$lastLoginAt" },
                },
              },
            ],
            as: "userStats",
          },
        },
        // Lookup con sesiones de usuario
        {
          $lookup: {
            from: "usersessions",
            let: { roleId: "$_id" },
            pipeline: [
              {
                $lookup: {
                  from: "users",
                  localField: "userId",
                  foreignField: "_id",
                  as: "user",
                },
              },
              { $unwind: "$user" },
              { $match: { $expr: { $in: ["$$roleId", "$user.roles"] } } },
              ...(dateFrom || dateTo
                ? [
                    {
                      $match: {
                        createdAt: {
                          ...(dateFrom && { $gte: new Date(dateFrom) }),
                          ...(dateTo && { $lte: new Date(dateTo) }),
                        },
                      },
                    },
                  ]
                : []),
              {
                $group: {
                  _id: null,
                  totalSessions: { $sum: 1 },
                  activeSessions: {
                    $sum: { $cond: [{ $eq: ["$isActive", true] }, 1, 0] },
                  },
                  avgSessionDuration: { $avg: "$metadata.sessionDuration" },
                  totalRequests: { $sum: "$metadata.totalRequests" },
                  suspiciousActivities: {
                    $sum: { $size: { $ifNull: ["$suspiciousActivity", []] } },
                  },
                },
              },
            ],
            as: "sessionStats",
          },
        },
        {
          $project: {
            roleName: 1,
            displayName: 1,
            hierarchy: 1,
            roleType: 1,
            isSystemRole: 1,
            permissions: { $size: "$permissions" },
            sessionConfig: 1,
            notificationSettings: 1,
            geographicRestrictions: 1,
            metadata: 1,
            userStats: { $arrayElemAt: ["$userStats", 0] },
            sessionStats: { $arrayElemAt: ["$sessionStats", 0] },
            createdAt: 1,
            updatedAt: 1,
          },
        },
      ];

      const result = await this.model.aggregate(pipeline);

      if (roleId) {
        return result[0] || null;
      }

      return result;
    } catch (error) {
      console.error("Error obteniendo analytics de roles:", error);
      throw error;
    }
  }

  /**
   * Obtener estadísticas generales de roles
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

      // Estadísticas por tipo de rol
      const typeStats = await this.model.aggregate([
        {
          $match: {
            isActive: true,
            $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
          },
        },
        {
          $group: {
            _id: "$roleType",
            count: { $sum: 1 },
            avgHierarchy: { $avg: "$hierarchy" },
            totalUsers: { $sum: "$stats.userCount" },
          },
        },
        { $sort: { count: -1 } },
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
        byType: typeStats,
      };
    } catch (error) {
      console.error("Error obteniendo estadísticas de roles:", error);
      throw error;
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
        roleType: role.roleType,
        totalPermissions: role.permissions?.length || 0,
        resourcesWithFullAccess: [],
        resourcesWithLimitedAccess: [],
        scopeDistribution: { none: 0, own: 0, company: 0, global: 0 },
        permissionsByResource: {},
        securityLevel: this.getSecurityLevel(role.hierarchy),
        requiresTwoFactor: role.sessionConfig?.requireTwoFactor || false,
        geographicRestrictions:
          role.geographicRestrictions?.restrictToGeolocation || false,
      };

      if (role.permissions) {
        role.permissions.forEach((permission) => {
          // Verificar si tiene acceso completo
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

          // Contar distribución de alcances
          summary.scopeDistribution[permission.scope]++;

          // Agrupar por recurso
          summary.permissionsByResource[permission.resource] = {
            actions: permission.actions,
            scope: permission.scope,
            conditions: permission.conditions,
            timeRestricted:
              permission.timeRestrictions?.businessHoursOnly || false,
            geoRestricted:
              permission.geographicRestrictions?.restrictToLocation || false,
          };
        });
      }

      return summary;
    } catch (error) {
      console.error("Error obteniendo resumen de permisos:", error);
      throw error;
    }
  }

  // ===== IMPORT/EXPORT Y CONFIGURACIÓN =====

  /**
   * Exportar configuración completa de roles
   * @param {Object} options - Opciones de exportación
   */
  async exportCompleteRoleConfiguration(options = {}) {
    try {
      const {
        includeSystemRoles = true,
        includeStats = true,
        includeUsage = false,
      } = options;

      const matchStage = includeSystemRoles ? {} : { isSystemRole: false };

      const pipeline = [
        { $match: { ...matchStage, isActive: true } },
        ...(includeUsage
          ? [
              {
                $lookup: {
                  from: "users",
                  let: { roleId: "$_id" },
                  pipeline: [
                    {
                      $match: {
                        $expr: { $in: ["$$roleId", "$roles"] },
                        isActive: true,
                      },
                    },
                    { $count: "count" },
                  ],
                  as: "activeUsers",
                },
              },
              {
                $addFields: {
                  activeUserCount: {
                    $ifNull: [{ $arrayElemAt: ["$activeUsers.count", 0] }, 0],
                  },
                },
              },
            ]
          : []),
        {
          $project: {
            __v: 0,
            ...(includeStats ? {} : { stats: 0 }),
            ...(includeUsage ? {} : { activeUsers: 0 }),
          },
        },
      ];

      const roles = await this.model.aggregate(pipeline);

      return {
        exportDate: new Date(),
        totalRoles: roles.length,
        includeSystemRoles,
        includeStats,
        includeUsage,
        roles: roles.map((role) => ({
          ...role,
          // Asegurar que los campos nuevos estén incluidos
          sessionConfig: role.sessionConfig || {},
          notificationSettings: role.notificationSettings || {},
          geographicRestrictions: role.geographicRestrictions || {},
          metadata: role.metadata || {},
        })),
      };
    } catch (error) {
      console.error("Error exportando configuración completa de roles:", error);
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
          displayName: {
            original: { language: "es", text: "Super Administrador" },
            translations: new Map([
              ["en", { text: "Super Administrator", translatedAt: new Date() }],
            ]),
          },
          description: {
            original: { language: "es", text: "Acceso completo al sistema" },
            translations: new Map([
              [
                "en",
                { text: "Complete system access", translatedAt: new Date() },
              ],
            ]),
          },
          hierarchy: 100,
          roleType: "system",
          isSystemRole: true,
          permissions: [{ resource: "all", actions: ["all"], scope: "global" }],
          companyRestrictions: {
            canManageAllCompanies: true,
            restrictedToOwnCompany: false,
          },
          sessionConfig: {
            maxConcurrentSessions: 5,
            sessionTimeoutMinutes: 720,
            requireTwoFactor: true,
            allowRememberMe: false,
          },
          notificationSettings: {
            enableSystemNotifications: true,
            enableBusinessNotifications: true,
            notificationChannels: ["email", "sms", "push", "in_app"],
            dailyDigest: true,
          },
          metadata: {
            color: "#FF0000",
            icon: "crown",
            category: "admin",
            priority: 10,
            sortOrder: 1,
          },
        },
        {
          roleName: "admin",
          displayName: {
            original: { language: "es", text: "Administrador" },
            translations: new Map([
              ["en", { text: "Administrator", translatedAt: new Date() }],
            ]),
          },
          description: {
            original: {
              language: "es",
              text: "Administrador del sistema con acceso limitado",
            },
            translations: new Map([
              [
                "en",
                {
                  text: "System administrator with limited access",
                  translatedAt: new Date(),
                },
              ],
            ]),
          },
          hierarchy: 80,
          roleType: "system",
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
          sessionConfig: {
            maxConcurrentSessions: 3,
            sessionTimeoutMinutes: 480,
            requireTwoFactor: true,
            allowRememberMe: true,
          },
          metadata: {
            color: "#FF6600",
            icon: "shield",
            category: "admin",
            priority: 8,
            sortOrder: 2,
          },
        },
        {
          roleName: "business_owner",
          displayName: {
            original: { language: "es", text: "Propietario de Empresa" },
            translations: new Map([
              ["en", { text: "Business Owner", translatedAt: new Date() }],
            ]),
          },
          description: {
            original: {
              language: "es",
              text: "Propietario que puede gestionar su empresa",
            },
            translations: new Map([
              [
                "en",
                {
                  text: "Owner who can manage their business",
                  translatedAt: new Date(),
                },
              ],
            ]),
          },
          hierarchy: 50,
          roleType: "business",
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
          sessionConfig: {
            maxConcurrentSessions: 3,
            sessionTimeoutMinutes: 480,
            requireTwoFactor: false,
            allowRememberMe: true,
          },
          metadata: {
            color: "#0066FF",
            icon: "building",
            category: "business",
            priority: 5,
            sortOrder: 3,
          },
        },
        {
          roleName: "customer",
          displayName: {
            original: { language: "es", text: "Cliente" },
            translations: new Map([
              ["en", { text: "Customer", translatedAt: new Date() }],
            ]),
          },
          description: {
            original: {
              language: "es",
              text: "Usuario cliente con permisos básicos",
            },
            translations: new Map([
              [
                "en",
                {
                  text: "Customer user with basic permissions",
                  translatedAt: new Date(),
                },
              ],
            ]),
          },
          hierarchy: 10,
          roleType: "customer",
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
          sessionConfig: {
            maxConcurrentSessions: 2,
            sessionTimeoutMinutes: 240,
            requireTwoFactor: false,
            allowRememberMe: true,
          },
          metadata: {
            color: "#00CC66",
            icon: "user",
            category: "customer",
            priority: 1,
            sortOrder: 4,
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
            console.log(
              `✅ Rol del sistema creado: ${roleData.displayName.original.text}`
            );
          } else {
            console.log(
              `ℹ️  Rol del sistema ya existe: ${roleData.displayName.original.text}`
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

  // ===== MÉTODOS AUXILIARES =====

  /**
   * Validar permisos con restricciones mejoradas
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
      "all",
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
      "moderate",
      "verify",
      "all",
    ];

    const validScopes = ["global", "company", "own", "none"];

    return permissions.map((permission) => {
      if (!validResources.includes(permission.resource)) {
        throw new Error(`Recurso inválido: ${permission.resource}`);
      }

      const actions = Array.isArray(permission.actions)
        ? permission.actions
        : [permission.actions];

      for (const action of actions) {
        if (!validActions.includes(action)) {
          throw new Error(`Acción inválida: ${action}`);
        }
      }

      if (!validScopes.includes(permission.scope)) {
        throw new Error(`Alcance inválido: ${permission.scope}`);
      }

      return {
        resource: permission.resource,
        actions: actions,
        scope: permission.scope || "own",
        conditions: permission.conditions || {},
        geographicRestrictions: {
          allowedCountries:
            permission.geographicRestrictions?.allowedCountries || [],
          allowedRegions:
            permission.geographicRestrictions?.allowedRegions || [],
          restrictToLocation: Boolean(
            permission.geographicRestrictions?.restrictToLocation
          ),
        },
        timeRestrictions: {
          businessHoursOnly: Boolean(
            permission.timeRestrictions?.businessHoursOnly
          ),
          timezone: permission.timeRestrictions?.timezone || "America/Lima",
          allowedDays: permission.timeRestrictions?.allowedDays || [
            1, 2, 3, 4, 5,
          ],
          allowedHours: {
            start: permission.timeRestrictions?.allowedHours?.start || "08:00",
            end: permission.timeRestrictions?.allowedHours?.end || "18:00",
          },
        },
      };
    });
  }

  /**
   * Verificar si un rol está expirado
   */
  isRoleExpired(role) {
    return role.expiresAt && role.expiresAt < new Date();
  }

  /**
   * Verificar si un rol puede gestionar empresa
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
   * Validar restricciones geográficas mejoradas
   */
  validateGeographicRestrictions(role, location) {
    const restrictions = role.geographicRestrictions;

    if (!restrictions || !restrictions.restrictToGeolocation) {
      return true;
    }

    // Validar país
    if (restrictions.allowedCountries?.length > 0) {
      if (
        !restrictions.allowedCountries.includes(location.country?.toUpperCase())
      ) {
        return false;
      }
    }

    // Validar región
    if (restrictions.allowedRegions?.length > 0) {
      if (!restrictions.allowedRegions.includes(location.region)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Validar restricciones de tiempo
   */
  validateTimeRestrictions(timeRestrictions, currentTime = new Date()) {
    if (!timeRestrictions.businessHoursOnly) {
      return true;
    }

    // Validar día de la semana (1 = Lunes, 7 = Domingo)
    const dayOfWeek = currentTime.getDay() || 7; // Convertir 0 (Domingo) a 7
    const allowedDays = timeRestrictions.allowedDays || [1, 2, 3, 4, 5];

    if (!allowedDays.includes(dayOfWeek)) {
      return false;
    }

    // Validar hora
    const currentHour = currentTime.getHours();
    const currentMinute = currentTime.getMinutes();
    const currentTimeMinutes = currentHour * 60 + currentMinute;

    const startTime = timeRestrictions.allowedHours?.start || "08:00";
    const endTime = timeRestrictions.allowedHours?.end || "18:00";

    const [startHour, startMin] = startTime.split(":").map(Number);
    const [endHour, endMin] = endTime.split(":").map(Number);

    const startTimeMinutes = startHour * 60 + startMin;
    const endTimeMinutes = endHour * 60 + endMin;

    return (
      currentTimeMinutes >= startTimeMinutes &&
      currentTimeMinutes <= endTimeMinutes
    );
  }

  /**
   * Obtener nivel de seguridad basado en jerarquía
   */
  getSecurityLevel(hierarchy) {
    if (hierarchy >= 90) return "critical";
    if (hierarchy >= 70) return "high";
    if (hierarchy >= 40) return "medium";
    return "standard";
  }
}
