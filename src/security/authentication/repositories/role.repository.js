// =============================================================================
// src/modules/authentication/repositories/role.repository.js
// Repositorio específico para Role extendiendo BaseRepository
// =============================================================================
import { BaseRepository } from "../../../modules/core/repositories/base.repository.js";
import { Role } from "../models/role.scheme.js";
import { Types } from "mongoose";
import {
  DEFAULT_LANGUAGE,
  SUPPORTED_LANGUAGES,
} from "../../../modules/core/models/multi_language_pattern_improved.scheme.js";

export class RoleRepository extends BaseRepository {
  constructor() {
    super(Role);
    this.initializeRoleConfig();
  }

  /**
   * Configuración específica del repositorio de roles
   */
  initializeRoleConfig() {
    // Campos específicos para búsqueda de texto en roles
    this.roleSearchFields = [
      "roleName",
      "displayName.original.text",
      "description.original.text",
      "metadata.category",
    ];
  }

  // =============================================================================
  // MÉTODOS ESPECÍFICOS DE ROLES
  // =============================================================================

  /**
   * Buscar rol por nombre único
   */
  async findByRoleName(roleName, options = {}) {
    try {
      const {
        includeInactive = false,
        populate = "",
        language = DEFAULT_LANGUAGE,
      } = options;

      const query = this.model.findOne({
        roleName: roleName.toLowerCase(),
      });

      // Filtrar por estado activo si es necesario
      if (!includeInactive) {
        query.where({ isRoleActive: true });
      }

      // Usar query helper del base para soft delete
      query.active();

      if (populate) {
        query.populate(populate);
      }

      const role = await query;

      if (!role) {
        return null;
      }

      // Agregar textos localizados si se especifica idioma
      if (language && language !== DEFAULT_LANGUAGE) {
        return this.addLocalizedTexts(role, language);
      }

      return role;
    } catch (error) {
      console.error("Error buscando rol por nombre:", error);
      throw new Error(`Error buscando rol: ${error.message}`);
    }
  }

  /**
   * Obtener roles por jerarquía
   */
  async findByHierarchyRange(minLevel = 0, maxLevel = 100, options = {}) {
    const { includeInactive = false, sort = { hierarchy: 1 } } = options;

    const filters = {
      hierarchy: { $gte: minLevel, $lte: maxLevel },
    };

    if (!includeInactive) {
      filters.isRoleActive = true;
    }

    return await this.findAll(filters, {
      ...options,
      sort,
    });
  }

  /**
   * Obtener roles del sistema
   */
  async getSystemRoles(options = {}) {
    const { includeInactive = false } = options;

    const filters = {
      isSystemRole: true,
    };

    if (!includeInactive) {
      filters.isRoleActive = true;
    }

    return await this.findAll(filters, {
      ...options,
      sort: { hierarchy: -1, "metadata.sortOrder": 1 },
    });
  }

  /**
   * Obtener rol por defecto
   */
  async getDefaultRole(options = {}) {
    const { language = DEFAULT_LANGUAGE } = options;

    const role = await this.model
      .findOne({
        isDefault: true,
        isRoleActive: true,
      })
      .active();

    if (role && language !== DEFAULT_LANGUAGE) {
      return this.addLocalizedTexts(role, language);
    }

    return role;
  }

  /**
   * Obtener roles por tipo
   */
  async getRolesByType(roleType, options = {}) {
    const { includeInactive = false } = options;

    const filters = {
      roleType: roleType,
    };

    if (!includeInactive) {
      filters.isRoleActive = true;
    }

    return await this.findAll(filters, {
      ...options,
      sort: { "metadata.sortOrder": 1, hierarchy: -1 },
    });
  }

  // =============================================================================
  // GESTIÓN DE PERMISOS
  // =============================================================================

  /**
   * Buscar roles con permiso específico
   */
  async findRolesWithPermission(resource, action, scope = null, options = {}) {
    const matchConditions = [
      { "permissions.resource": resource },
      { "permissions.resource": "all" },
    ];

    const pipeline = [
      {
        $match: {
          $or: matchConditions,
          isRoleActive: true,
        },
      },
      {
        $addFields: {
          hasMatchingPermission: {
            $anyElementTrue: {
              $map: {
                input: "$permissions",
                as: "permission",
                in: {
                  $and: [
                    {
                      $or: [
                        { $eq: ["$$permission.resource", resource] },
                        { $eq: ["$$permission.resource", "all"] },
                      ],
                    },
                    {
                      $or: [
                        { $in: [action, "$$permission.actions"] },
                        { $in: ["manage", "$$permission.actions"] },
                        { $in: ["all", "$$permission.actions"] },
                      ],
                    },
                    scope
                      ? {
                          $gte: [
                            this.getScopeLevel("$$permission.scope"),
                            this.getScopeLevel(scope),
                          ],
                        }
                      : true,
                  ],
                },
              },
            },
          },
        },
      },
      {
        $match: { hasMatchingPermission: true },
      },
      {
        $sort: { hierarchy: -1 },
      },
    ];

    return await this.executeAggregationPipeline({
      pipeline,
      options: { enablePagination: false, ...options },
    });
  }

  /**
   * Agregar permiso a un rol
   */
  async addPermissionToRole(roleId, permissionData, userData) {
    if (!Types.ObjectId.isValid(roleId)) {
      throw new Error("ID de rol no válido");
    }

    const role = await this.model.findById(roleId);
    if (!role || role.isDeleted) {
      throw new Error("Rol no encontrado");
    }

    // Usar método del modelo para agregar permiso
    role.addPermission(
      permissionData.resource,
      permissionData.actions,
      permissionData.scope,
      permissionData.conditions
    );

    role.updatedBy = userData.userId;
    role.lastChangeReason = `Permiso agregado: ${permissionData.resource}`;

    return await role.save();
  }

  /**
   * Remover permiso de un rol
   */
  async removePermissionFromRole(roleId, resource, action = null, userData) {
    if (!Types.ObjectId.isValid(roleId)) {
      throw new Error("ID de rol no válido");
    }

    const role = await this.model.findById(roleId);
    if (!role || role.isDeleted) {
      throw new Error("Rol no encontrado");
    }

    // Usar método del modelo para remover permiso
    role.removePermission(resource, action);

    role.updatedBy = userData.userId;
    role.lastChangeReason = `Permiso removido: ${resource}${action ? ` (${action})` : ""}`;

    return await role.save();
  }

  // =============================================================================
  // ESTADÍSTICAS Y ANÁLISIS
  // =============================================================================

  /**
   * Obtener estadísticas generales de roles
   */
  async getRoleStatistics(options = {}) {
    const pipeline = [
      {
        $facet: {
          // Estadísticas generales
          overview: [
            {
              $group: {
                _id: null,
                totalRoles: { $sum: 1 },
                activeRoles: {
                  $sum: { $cond: [{ $eq: ["$isRoleActive", true] }, 1, 0] },
                },
                systemRoles: {
                  $sum: { $cond: [{ $eq: ["$isSystemRole", true] }, 1, 0] },
                },
                customRoles: {
                  $sum: { $cond: [{ $eq: ["$isSystemRole", false] }, 1, 0] },
                },
                totalUsers: { $sum: "$stats.userCount" },
                avgHierarchy: { $avg: "$hierarchy" },
              },
            },
          ],

          // Distribución por tipo
          byType: [
            {
              $group: {
                _id: "$roleType",
                count: { $sum: 1 },
                avgUsers: { $avg: "$stats.userCount" },
                totalUsers: { $sum: "$stats.userCount" },
              },
            },
            { $sort: { count: -1 } },
          ],

          // Distribución por categoría
          byCategory: [
            {
              $group: {
                _id: "$metadata.category",
                count: { $sum: 1 },
                avgUsers: { $avg: "$stats.userCount" },
              },
            },
            { $sort: { count: -1 } },
          ],

          // Top roles por usuarios
          topByUsers: [
            { $sort: { "stats.userCount": -1 } },
            { $limit: 10 },
            {
              $project: {
                roleName: 1,
                "stats.userCount": 1,
                hierarchy: 1,
                roleType: 1,
              },
            },
          ],

          // Roles sin usuarios
          unusedRoles: [
            { $match: { "stats.userCount": { $lte: 0 } } },
            {
              $project: {
                roleName: 1,
                createdAt: 1,
                "stats.lastAssigned": 1,
              },
            },
          ],
        },
      },
    ];

    const result = await this.executeAggregationPipeline({
      pipeline,
      options: { enablePagination: false },
    });

    return result[0] || {};
  }

  /**
   * Análisis de permisos por rol
   */
  async getPermissionAnalysis(options = {}) {
    const pipeline = [
      {
        $unwind: "$permissions",
      },
      {
        $group: {
          _id: {
            resource: "$permissions.resource",
            action: { $arrayElemAt: ["$permissions.actions", 0] },
            scope: "$permissions.scope",
          },
          rolesCount: { $sum: 1 },
          roles: {
            $push: {
              roleName: "$roleName",
              hierarchy: "$hierarchy",
            },
          },
        },
      },
      {
        $group: {
          _id: "$_id.resource",
          permissions: {
            $push: {
              action: "$_id.action",
              scope: "$_id.scope",
              rolesCount: "$rolesCount",
              roles: "$roles",
            },
          },
          totalRoles: { $sum: "$rolesCount" },
        },
      },
      { $sort: { totalRoles: -1 } },
    ];

    return await this.executeAggregationPipeline({
      pipeline,
      options: { enablePagination: false, ...options },
    });
  }

  // =============================================================================
  // GESTIÓN DE JERARQUÍAS
  // =============================================================================

  /**
   * Validar jerarquía de roles
   */
  async validateRoleHierarchy(roleId, newHierarchy) {
    const role = await this.findById(roleId);

    if (role.parentRole) {
      const parentRole = await this.findById(role.parentRole);
      if (parentRole && newHierarchy >= parentRole.hierarchy) {
        throw new Error("La jerarquía debe ser menor que la del rol padre");
      }
    }

    // Verificar roles hijos
    const childRoles = await this.model
      .find({
        parentRole: roleId,
        isRoleActive: true,
      })
      .active();

    const invalidChildren = childRoles.filter(
      (child) => child.hierarchy >= newHierarchy
    );

    if (invalidChildren.length > 0) {
      throw new Error("La jerarquía debe ser mayor que la de los roles hijos");
    }

    return true;
  }

  /**
   * Obtener árbol jerárquico de roles
   */
  async getRoleHierarchyTree(options = {}) {
    const { maxDepth = 5, includeInactive = false } = options;

    const pipeline = [
      {
        $match: includeInactive ? {} : { isRoleActive: true },
      },
      {
        $lookup: {
          from: "roles",
          let: { roleId: "$_id" },
          pipeline: [
            {
              $match: {
                $expr: { $eq: ["$parentRole", "$$roleId"] },
                ...(includeInactive ? {} : { isRoleActive: true }),
              },
            },
            { $project: { roleName: 1, hierarchy: 1, roleType: 1 } },
          ],
          as: "children",
        },
      },
      {
        $project: {
          roleName: 1,
          hierarchy: 1,
          roleType: 1,
          parentRole: 1,
          children: 1,
          childCount: { $size: "$children" },
        },
      },
      { $sort: { hierarchy: -1, roleName: 1 } },
    ];

    return await this.executeAggregationPipeline({
      pipeline,
      options: { enablePagination: false },
    });
  }

  // =============================================================================
  // GESTIÓN MULTIIDIOMA
  // =============================================================================

  /**
   * Buscar roles con soporte multiidioma
   */
  async searchRolesWithLanguage(
    searchParams,
    language = DEFAULT_LANGUAGE,
    options = {}
  ) {
    const { text } = searchParams;

    const searchFields = [
      "roleName",
      "displayName.original.text",
      "description.original.text",
    ];

    // Si no es el idioma por defecto, agregar campos de traducción
    if (language !== DEFAULT_LANGUAGE) {
      searchFields.push(
        `displayName.translations.${language}.text`,
        `description.translations.${language}.text`
      );
    }

    const result = await this.search(
      { ...searchParams, text },
      { ...options, searchFields }
    );

    // Agregar textos localizados a los resultados
    if (result.docs && language !== DEFAULT_LANGUAGE) {
      result.docs = result.docs.map((role) =>
        this.addLocalizedTexts(role, language)
      );
    }

    return result;
  }

  /**
   * Actualizar traducciones de un rol
   */
  async updateRoleTranslation(roleId, language, translations, userData) {
    if (!SUPPORTED_LANGUAGES.includes(language)) {
      throw new Error(`Idioma no soportado: ${language}`);
    }

    const role = await this.model.findById(roleId);
    if (!role || role.isDeleted) {
      throw new Error("Rol no encontrado");
    }

    let updated = false;

    // Actualizar displayName si se proporciona
    if (translations.displayName && role.displayName) {
      role.displayName.addTranslation(language, translations.displayName, {
        method: "manual",
        service: "manual",
      });
      updated = true;
    }

    // Actualizar description si se proporciona
    if (translations.description && role.description) {
      role.description.addTranslation(language, translations.description, {
        method: "manual",
        service: "manual",
      });
      updated = true;
    }

    if (updated) {
      role.updatedBy = userData.userId;
      role.lastChangeReason = `Traducciones actualizadas para idioma: ${language}`;
      await role.save();
    }

    return role;
  }

  // =============================================================================
  // GESTIÓN DE USUARIOS ASIGNADOS
  // =============================================================================

  /**
   * Actualizar estadísticas de usuarios asignados
   */
  async updateUserStats(roleId) {
    const User = this.model.db.model("User");

    const userCount = await User.countDocuments({
      roles: roleId,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });

    return await this.model.findByIdAndUpdate(
      roleId,
      {
        "stats.userCount": userCount,
        "stats.lastUsed": new Date(),
        updatedAt: new Date(),
      },
      { new: true }
    );
  }

  /**
   * Obtener usuarios por rol
   */
  async getUsersByRole(roleId, options = {}) {
    const User = this.model.db.model("User");

    return await User.find(
      {
        roles: roleId,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
      null,
      options
    );
  }

  // =============================================================================
  // MÉTODOS DE VALIDACIÓN Y CONFIGURACIÓN
  // =============================================================================

  /**
   * Validar configuración de rol antes de crear/actualizar
   */
  async validateRoleConfig(roleData, isUpdate = false, roleId = null) {
    const errors = [];

    // Validar nombre único
    if (roleData.roleName) {
      const existing = await this.model.findOne({
        roleName: roleData.roleName.toLowerCase(),
        ...(isUpdate && roleId ? { _id: { $ne: roleId } } : {}),
      });

      if (existing) {
        errors.push("El nombre del rol ya existe");
      }
    }

    // Validar que solo haya un rol por defecto
    if (roleData.isDefault) {
      const existingDefault = await this.model.findOne({
        isDefault: true,
        ...(isUpdate && roleId ? { _id: { $ne: roleId } } : {}),
      });

      if (existingDefault) {
        errors.push("Ya existe un rol por defecto");
      }
    }

    // Validar permisos
    if (roleData.permissions) {
      for (const permission of roleData.permissions) {
        if (
          !permission.resource ||
          !permission.actions ||
          permission.actions.length === 0
        ) {
          errors.push("Los permisos deben tener recurso y al menos una acción");
        }
      }
    }

    if (errors.length > 0) {
      throw new Error(`Errores de validación: ${errors.join(", ")}`);
    }

    return true;
  }

  /**
   * Crear roles del sistema
   */
  async createSystemRoles(userData) {
    try {
      return await this.model.createSystemRoles();
    } catch (error) {
      console.error("Error creando roles del sistema:", error);
      throw new Error(`Error creando roles del sistema: ${error.message}`);
    }
  }

  // =============================================================================
  // MÉTODOS AUXILIARES
  // =============================================================================

  /**
   * Agregar textos localizados a un rol
   */
  addLocalizedTexts(role, language) {
    const roleObj = role.toObject ? role.toObject() : role;

    if (roleObj.displayName) {
      const displayResult = role.displayName.getText
        ? role.displayName.getText(language)
        : { text: roleObj.displayName.original?.text || role.roleName };

      roleObj.localizedDisplayName = displayResult.text;
    }

    if (roleObj.description) {
      const descResult = role.description.getText
        ? role.description.getText(language)
        : { text: roleObj.description.original?.text || "" };

      roleObj.localizedDescription = descResult.text;
    }

    return roleObj;
  }

  /**
   * Obtener nivel numérico de scope para comparaciones
   */
  getScopeLevel(scope) {
    const levels = { none: 0, own: 1, company: 2, global: 3 };
    return levels[scope] || 0;
  }

  /**
   * Override de getTextSearchFields para incluir campos específicos de roles
   */
  getTextSearchFields() {
    return this.roleSearchFields;
  }
}

// Exportar instancia singleton
export const roleRepository = new RoleRepository();
export default roleRepository;
