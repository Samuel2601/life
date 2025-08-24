// =============================================================================
// src/modules/authentication/models/user/methods/static.methods.js
// =============================================================================

/**
 * Configurar métodos estáticos para el schema de Usuario
 * @param {mongoose.Schema} schema - El schema al que agregar los métodos estáticos
 */
export function setupStaticMethods(schema) {
  // Buscar usuario por email
  schema.statics.findByEmail = function (email) {
    return this.findOne({ email: email.toLowerCase() }).select("+passwordHash");
  };

  // Buscar usuario por token de verificación
  schema.statics.findByVerificationToken = function (token) {
    return this.findOne({
      emailVerificationToken: token,
      emailVerificationExpires: { $gt: Date.now() },
    });
  };

  // Buscar usuario por token de reset de contraseña
  schema.statics.findByPasswordResetToken = function (token) {
    return this.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() },
    });
  };

  // Buscar usuarios activos con paginación
  schema.statics.findActiveUsers = function (options = {}) {
    const {
      page = 1,
      limit = 10,
      sortBy = "createdAt",
      sortOrder = -1,
      search = "",
      language = null,
    } = options;

    let query = this.find({
      isActive: true,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });

    // Búsqueda por texto
    if (search) {
      query = query.find({
        $text: { $search: search },
      });
    }

    // Filtro por idioma
    if (language) {
      query = query.find({
        "preferences.language": language,
      });
    }

    // Ordenamiento
    const sort = {};
    sort[sortBy] = sortOrder;

    return query
      .sort(sort)
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate("roles", "roleName displayName")
      .lean();
  };

  // Estadísticas de usuarios
  schema.statics.getUserStats = async function () {
    const stats = await this.aggregate([
      {
        $group: {
          _id: null,
          totalUsers: { $sum: 1 },
          activeUsers: {
            $sum: {
              $cond: [{ $eq: ["$isActive", true] }, 1, 0],
            },
          },
          verifiedUsers: {
            $sum: {
              $cond: [{ $eq: ["$isEmailVerified", true] }, 1, 0],
            },
          },
          deletedUsers: {
            $sum: {
              $cond: [{ $eq: ["$isDeleted", true] }, 1, 0],
            },
          },
          usersWithOAuth: {
            $sum: {
              $cond: [
                {
                  $or: [
                    { $exists: ["$oauthProviders.google.providerId", true] },
                    { $exists: ["$oauthProviders.facebook.providerId", true] },
                    { $exists: ["$oauthProviders.apple.providerId", true] },
                    { $exists: ["$oauthProviders.microsoft.providerId", true] },
                  ],
                },
                1,
                0,
              ],
            },
          },
        },
      },
      {
        $project: {
          _id: 0,
          totalUsers: 1,
          activeUsers: 1,
          verifiedUsers: 1,
          deletedUsers: 1,
          usersWithOAuth: 1,
          inactiveUsers: { $subtract: ["$totalUsers", "$activeUsers"] },
          verificationRate: {
            $multiply: [{ $divide: ["$verifiedUsers", "$totalUsers"] }, 100],
          },
          oauthAdoptionRate: {
            $multiply: [{ $divide: ["$usersWithOAuth", "$totalUsers"] }, 100],
          },
        },
      },
    ]);

    return (
      stats[0] || {
        totalUsers: 0,
        activeUsers: 0,
        verifiedUsers: 0,
        deletedUsers: 0,
        inactiveUsers: 0,
        usersWithOAuth: 0,
        verificationRate: 0,
        oauthAdoptionRate: 0,
      }
    );
  };

  // Usuarios por idioma
  schema.statics.getUsersByLanguage = async function () {
    return await this.aggregate([
      {
        $match: {
          isActive: true,
          $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
        },
      },
      {
        $group: {
          _id: "$preferences.language",
          count: { $sum: 1 },
          users: {
            $push: {
              id: "$_id",
              fullName: {
                $concat: ["$profile.firstName", " ", "$profile.lastName"],
              },
              email: "$email",
              lastLoginAt: "$lastLoginAt",
            },
          },
        },
      },
      {
        $sort: { count: -1 },
      },
    ]);
  };

  // Limpiar tokens expirados
  schema.statics.cleanExpiredTokens = async function () {
    const result = await this.updateMany(
      {
        $or: [
          {
            emailVerificationExpires: { $lt: new Date() },
            emailVerificationToken: { $exists: true },
          },
          {
            passwordResetExpires: { $lt: new Date() },
            passwordResetToken: { $exists: true },
          },
        ],
      },
      {
        $unset: {
          emailVerificationToken: 1,
          emailVerificationExpires: 1,
          passwordResetToken: 1,
          passwordResetExpires: 1,
        },
      }
    );

    return result;
  };
}
