import mongoose from "mongoose";

export function applyStaticMethods(schema) {
  // Buscar por nombre
  schema.statics.findByName = function (roleName) {
    return this.findOne({
      roleName: roleName.toLowerCase(),
      isActive: true,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });
  };

  // Buscar por jerarquía
  schema.statics.findByHierarchy = function (minLevel = 0, maxLevel = 100) {
    return this.find({
      hierarchy: { $gte: minLevel, $lte: maxLevel },
      isActive: true,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    }).sort({ hierarchy: 1 });
  };

  // Obtener roles del sistema
  schema.statics.getSystemRoles = function () {
    return this.find({
      isSystemRole: true,
      isActive: true,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    }).sort({ hierarchy: 1 });
  };

  // Obtener rol por defecto
  schema.statics.getDefaultRole = function () {
    return this.findOne({
      isDefault: true,
      isActive: true,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });
  };

  // Obtener roles por tipo con paginación
  schema.statics.getRolesByType = function (roleType, options = {}) {
    const query = {
      roleType: roleType,
      isActive: true,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    };

    const queryObj = this.find(query);

    if (options.populate) {
      queryObj.populate(options.populate);
    }

    if (options.sortBy) {
      const sort = {};
      sort[options.sortBy] = options.sortOrder === "desc" ? -1 : 1;
      queryObj.sort(sort);
    } else {
      queryObj.sort({ "metadata.sortOrder": 1, hierarchy: -1 });
    }

    if (options.limit) {
      queryObj.limit(options.limit);
    }

    return queryObj;
  };

  // Crear roles del sistema
  schema.statics.createSystemRoles = async function () {
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
        metadata: {
          color: "#FF0000",
          icon: "crown",
          category: "admin",
          priority: 10,
          sortOrder: 1,
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
          { resource: "businesses", actions: ["read", "update"], scope: "own" },
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
          const role = new this(roleData);
          await role.save();
          createdRoles.push(role);
          console.log(
            `✅ Rol del sistema creado: ${roleData.displayName.original.text}`
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
  };

  // Actualizar estadísticas del rol
  schema.statics.updateRoleStats = async function (roleId) {
    const User = mongoose.model("User");

    const userCount = await User.countDocuments({
      roles: roleId,
      isActive: true,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });

    await this.findByIdAndUpdate(roleId, {
      "stats.userCount": userCount,
      "stats.lastAssigned": new Date(),
    });

    return userCount;
  };
}
