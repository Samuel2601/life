// =============================================================================
// src/security/authentication/middlewares/role.middleware.js
// =============================================================================
import { RoleRepository } from "../repositories/role.repository.js";
import {
  AuthError,
  AuthErrorCodes,
  AuthConstants,
} from "../authentication.index.js";

/**
 * Middleware para verificar roles específicos
 * @param {Array|string} requiredRoles - Roles requeridos
 * @param {Object} options - Opciones adicionales
 */
export const requireRole = (requiredRoles, options = {}) => {
  const { requireAll = false, allowSuperAdmin = true } = options;

  // Normalizar a array
  const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

  return async (req, res, next) => {
    try {
      // Verificar autenticación
      if (!req.user || !req.session) {
        return res.status(401).json({
          success: false,
          error: "Autenticación requerida",
          code: AuthErrorCodes.PERMISSION_DENIED,
        });
      }

      // Super admin siempre tiene acceso (si está habilitado)
      if (
        allowSuperAdmin &&
        req.user.roles?.includes(AuthConstants.SYSTEM_ROLES.SUPER_ADMIN)
      ) {
        return next();
      }

      const userRoles = req.user.roles || [];

      // Verificar si tiene los roles requeridos
      let hasPermission = false;

      if (requireAll) {
        // Debe tener TODOS los roles
        hasPermission = roles.every((role) => userRoles.includes(role));
      } else {
        // Debe tener AL MENOS UNO de los roles
        hasPermission = roles.some((role) => userRoles.includes(role));
      }

      if (!hasPermission) {
        return res.status(403).json({
          success: false,
          error: "No tienes los permisos necesarios",
          code: AuthErrorCodes.INSUFFICIENT_PERMISSIONS,
          requiredRoles: roles,
          userRoles: userRoles,
        });
      }

      next();
    } catch (error) {
      console.error("Error verificando roles:", error);

      res.status(500).json({
        success: false,
        error: "Error interno verificando permisos",
        code: "ROLE_VERIFICATION_ERROR",
      });
    }
  };
};

/**
 * Middleware para verificar permisos específicos
 * @param {string} resource - Recurso al que se quiere acceder
 * @param {string} action - Acción que se quiere realizar
 * @param {string} scope - Alcance del permiso
 */
export const requirePermission = (resource, action, scope = "own") => {
  return async (req, res, next) => {
    try {
      // Verificar autenticación
      if (!req.user || !req.session) {
        return res.status(401).json({
          success: false,
          error: "Autenticación requerida",
          code: AuthErrorCodes.PERMISSION_DENIED,
        });
      }

      // Super admin siempre tiene acceso
      if (req.user.roles?.includes(AuthConstants.SYSTEM_ROLES.SUPER_ADMIN)) {
        return next();
      }

      const roleRepository = new RoleRepository();
      const userRoles = req.user.roles || [];

      // Verificar permisos en todos los roles del usuario
      let hasPermission = false;

      for (const roleId of userRoles) {
        try {
          const role = await roleRepository.findById(roleId);

          if (role && role.hasPermission(resource, action, scope)) {
            hasPermission = true;
            break;
          }
        } catch (roleError) {
          console.error(`Error verificando rol ${roleId}:`, roleError);
        }
      }

      if (!hasPermission) {
        return res.status(403).json({
          success: false,
          error: "No tienes permisos para realizar esta acción",
          code: AuthErrorCodes.INSUFFICIENT_PERMISSIONS,
          requiredPermission: {
            resource,
            action,
            scope,
          },
        });
      }

      next();
    } catch (error) {
      console.error("Error verificando permisos:", error);

      res.status(500).json({
        success: false,
        error: "Error interno verificando permisos",
        code: "PERMISSION_VERIFICATION_ERROR",
      });
    }
  };
};

/**
 * Middleware para verificar jerarquía de roles
 * @param {number} minHierarchy - Jerarquía mínima requerida
 */
export const requireHierarchy = (minHierarchy) => {
  return async (req, res, next) => {
    try {
      if (!req.user || !req.session) {
        return res.status(401).json({
          success: false,
          error: "Autenticación requerida",
          code: AuthErrorCodes.PERMISSION_DENIED,
        });
      }

      const roleRepository = new RoleRepository();
      const userRoles = req.user.roles || [];

      let maxHierarchy = 0;

      // Obtener la jerarquía más alta del usuario
      for (const roleId of userRoles) {
        try {
          const role = await roleRepository.findById(roleId);
          if (role && role.hierarchy > maxHierarchy) {
            maxHierarchy = role.hierarchy;
          }
        } catch (roleError) {
          console.error(`Error obteniendo rol ${roleId}:`, roleError);
        }
      }

      if (maxHierarchy < minHierarchy) {
        return res.status(403).json({
          success: false,
          error: "Nivel de acceso insuficiente",
          code: AuthErrorCodes.INSUFFICIENT_PERMISSIONS,
          requiredHierarchy: minHierarchy,
          userHierarchy: maxHierarchy,
        });
      }

      // Agregar jerarquía al request para uso posterior
      req.userHierarchy = maxHierarchy;

      next();
    } catch (error) {
      console.error("Error verificando jerarquía:", error);

      res.status(500).json({
        success: false,
        error: "Error interno verificando jerarquía",
        code: "HIERARCHY_VERIFICATION_ERROR",
      });
    }
  };
};

/**
 * Middleware para verificar roles activos y no expirados
 */
export const validateActiveRoles = async (req, res, next) => {
  try {
    if (!req.user || !req.session) {
      return next(); // Dejar que otros middlewares manejen la autenticación
    }

    const roleRepository = new RoleRepository();
    const userRoles = req.user.roles || [];
    const activeRoles = [];

    // Verificar cada rol del usuario
    for (const roleId of userRoles) {
      try {
        const role = await roleRepository.findById(roleId);

        if (role && role.isActive && !roleRepository.isRoleExpired(role)) {
          activeRoles.push(roleId);
        }
      } catch (roleError) {
        console.error(`Error validando rol ${roleId}:`, roleError);
      }
    }

    // Actualizar roles activos en el request
    req.user.activeRoles = activeRoles;

    // Si no tiene roles activos, podría ser problemático
    if (activeRoles.length === 0 && userRoles.length > 0) {
      console.warn(`⚠️ Usuario ${req.user.id} no tiene roles activos válidos`);
    }

    next();
  } catch (error) {
    console.error("Error validando roles activos:", error);
    next(); // Continuar aunque falle la validación
  }
};

/**
 * Middleware para roles específicos del negocio
 */
export const requireBusinessRole = () => {
  return requireRole([
    AuthConstants.SYSTEM_ROLES.BUSINESS_OWNER,
    AuthConstants.SYSTEM_ROLES.ADMIN,
    AuthConstants.SYSTEM_ROLES.SUPER_ADMIN,
  ]);
};

/**
 * Middleware para roles administrativos
 */
export const requireAdminRole = () => {
  return requireRole([
    AuthConstants.SYSTEM_ROLES.ADMIN,
    AuthConstants.SYSTEM_ROLES.SUPER_ADMIN,
  ]);
};

/**
 * Middleware para super admin únicamente
 */
export const requireSuperAdminRole = () => {
  return requireRole(AuthConstants.SYSTEM_ROLES.SUPER_ADMIN, {
    allowSuperAdmin: false, // Verificación explícita
  });
};

/**
 * Middleware para verificar propiedad del negocio
 * @param {string} businessIdField - Campo que contiene el ID del negocio
 */
export const requireBusinessOwnership = (businessIdField = "businessId") => {
  return async (req, res, next) => {
    try {
      if (!req.user || !req.session) {
        return res.status(401).json({
          success: false,
          error: "Autenticación requerida",
          code: AuthErrorCodes.PERMISSION_DENIED,
        });
      }

      // Super admin puede acceder a todo
      if (req.user.roles?.includes(AuthConstants.SYSTEM_ROLES.SUPER_ADMIN)) {
        return next();
      }

      // Admin puede acceder a todo
      if (req.user.roles?.includes(AuthConstants.SYSTEM_ROLES.ADMIN)) {
        return next();
      }

      // Verificar si es propietario del negocio
      let businessId = null;

      if (req.params[businessIdField]) {
        businessId = req.params[businessIdField];
      } else if (req.body[businessIdField]) {
        businessId = req.body[businessIdField];
      } else if (req.query[businessIdField]) {
        businessId = req.query[businessIdField];
      }

      if (!businessId) {
        return res.status(400).json({
          success: false,
          error: `Campo ${businessIdField} requerido`,
          code: "MISSING_BUSINESS_ID",
        });
      }

      // TODO: Verificar propiedad del negocio en la base de datos
      // const business = await BusinessRepository.findById(businessId);
      // if (!business || business.ownerId.toString() !== req.user.id.toString()) {
      //   return res.status(403).json({
      //     success: false,
      //     error: "No eres propietario de este negocio",
      //     code: AuthErrorCodes.PERMISSION_DENIED,
      //   });
      // }

      next();
    } catch (error) {
      console.error("Error verificando propiedad del negocio:", error);

      res.status(500).json({
        success: false,
        error: "Error interno verificando propiedad",
        code: "BUSINESS_OWNERSHIP_ERROR",
      });
    }
  };
};

/**
 * Middleware dinámico para permisos basados en contexto
 * @param {Function} permissionChecker - Función que determina permisos
 */
export const dynamicPermission = (permissionChecker) => {
  return async (req, res, next) => {
    try {
      if (!req.user || !req.session) {
        return res.status(401).json({
          success: false,
          error: "Autenticación requerida",
          code: AuthErrorCodes.PERMISSION_DENIED,
        });
      }

      const hasPermission = await permissionChecker(req);

      if (!hasPermission) {
        return res.status(403).json({
          success: false,
          error: "No tienes permisos para realizar esta acción",
          code: AuthErrorCodes.INSUFFICIENT_PERMISSIONS,
        });
      }

      next();
    } catch (error) {
      console.error("Error en verificación dinámica de permisos:", error);

      res.status(500).json({
        success: false,
        error: "Error interno verificando permisos",
        code: "DYNAMIC_PERMISSION_ERROR",
      });
    }
  };
};

// Exportar también como default
export default {
  requireRole,
  requirePermission,
  requireHierarchy,
  validateActiveRoles,
  requireBusinessRole,
  requireAdminRole,
  requireSuperAdminRole,
  requireBusinessOwnership,
  dynamicPermission,
};
