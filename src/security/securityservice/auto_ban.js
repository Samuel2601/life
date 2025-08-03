// src/middlewares/autoBan.js
import { AutoBanSystem } from "../security/autoBanSystem.js";
import { auth } from "./auth.js";

// Instancia única del sistema de baneos
const autoBanSystem = new AutoBanSystem();

// Middleware principal de baneos automáticos
export const autoBanMiddleware = (req, res, next) => {
  const ip = autoBanSystem.getRealIP(req);
  const userAgent = req.get("User-Agent") || "N/A";
  const path = req.path;
  const method = req.method;

  // Log básico de la request
  console.log(
    `📥 ${new Date().toISOString()} - ${method} ${path} - IP: ${ip} - UA: ${userAgent.substring(
      0,
      50
    )}`
  );

  // Analizar la request
  const analysis = autoBanSystem.analyzeRequest(req);

  // Si está en whitelist, continuar sin más análisis
  if (analysis.isWhitelisted) {
    return next();
  }

  // Si está baneada, bloquear inmediatamente
  if (analysis.isBanned) {
    console.log(`🚫 [AutoBan] BLOQUEADO: ${ip} - IP en lista de baneos`);

    // Log del intento de acceso de IP baneada
    autoBanSystem.logSecurity("BLOCKED_ACCESS", {
      ip,
      path,
      method,
      userAgent,
      timestamp: new Date().toISOString(),
    });

    return res.status(403).json({
      success: false,
      message: "Acceso denegado - IP bloqueada por actividad sospechosa",
      code: "IP_BANNED",
      timestamp: new Date().toISOString(),
    });
  }

  // Si se debe banear (nuevo ban), bloquear
  if (analysis.shouldBan) {
    console.log(
      `🚨 [AutoBan] NUEVO BAN: ${ip} - Score: ${analysis.suspicionScore}`
    );

    return res.status(403).json({
      success: false,
      message: "Actividad sospechosa detectada - Acceso denegado",
      code: "SUSPICIOUS_ACTIVITY",
      timestamp: new Date().toISOString(),
    });
  }

  // Log actividad sospechosa sin banear aún
  if (analysis.suspicionScore > 5) {
    console.log(
      `⚠️ [AutoBan] SOSPECHOSO: ${ip} - Score: ${
        analysis.suspicionScore
      } - Requests: ${
        analysis.recentRequests
      }/min - Patrones: ${analysis.patterns.join(", ")}`
    );
  }

  // Log actividad normal para IPs nuevas
  if (analysis.activityCount === 1) {
    console.log(`👋 [AutoBan] NUEVA IP: ${ip} - Primera request a ${path}`);
  }

  next();
};

// Middleware para logging de respuestas con IP real
export const responseLoggerMiddleware = (req, res, next) => {
  const start = Date.now();
  const realIP = autoBanSystem.getRealIP(req);

  res.on("finish", () => {
    const duration = Date.now() - start;
    const statusEmoji =
      res.statusCode >= 400 ? "❌" : res.statusCode >= 300 ? "⚠️" : "✅";

    console.log(
      `📤 ${statusEmoji} ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms - ${realIP}`
    );

    // Log responses 404 para análisis
    if (res.statusCode === 404) {
      autoBanSystem.logSecurity("404_REQUEST", {
        ip: realIP,
        path: req.path,
        method: req.method,
        userAgent: req.get("User-Agent"),
        timestamp: new Date().toISOString(),
        duration,
      });
    }
  });

  next();
};

// Middleware para rate limiting personalizado basado en IP real
export const createSmartRateLimit = (options = {}) => {
  const defaults = {
    windowMs: 15 * 60 * 1000, // 15 minutos
    maxRequests: 100,
    productionMax: 100,
    developmentMax: 1000,
    skipWhitelisted: true,
  };

  const config = { ...defaults, ...options };
  const requestCounts = new Map();

  // Limpiar contadores cada ventana de tiempo
  setInterval(() => {
    requestCounts.clear();
  }, config.windowMs);

  return (req, res, next) => {
    const ip = autoBanSystem.getRealIP(req);

    // Saltar rate limiting para IPs whitelistadas
    if (config.skipWhitelisted && autoBanSystem.isWhitelisted(ip)) {
      return next();
    }

    // Saltar rate limiting para IPs ya baneadas (se manejan en autoBanMiddleware)
    if (autoBanSystem.isBanned(ip)) {
      return next();
    }

    const now = Date.now();
    const windowStart = Math.floor(now / config.windowMs) * config.windowMs;
    const key = `${ip}-${windowStart}`;

    const currentCount = requestCounts.get(key) || 0;
    const maxAllowed =
      process.env.NODE_ENV === "production"
        ? config.productionMax
        : config.developmentMax;

    if (currentCount >= maxAllowed) {
      console.log(
        `⏰ [RateLimit] LÍMITE EXCEDIDO: ${ip} - ${currentCount}/${maxAllowed} requests`
      );

      // Log del rate limit excedido
      autoBanSystem.logSecurity("RATE_LIMIT_EXCEEDED", {
        ip,
        count: currentCount,
        limit: maxAllowed,
        path: req.path,
        method: req.method,
        timestamp: new Date().toISOString(),
      });

      return res.status(429).json({
        success: false,
        message: "Demasiadas solicitudes desde esta IP, intenta más tarde.",
        retryAfter: Math.ceil(config.windowMs / 1000 / 60) + " minutos",
        code: "RATE_LIMIT_EXCEEDED",
        timestamp: new Date().toISOString(),
      });
    }

    requestCounts.set(key, currentCount + 1);
    next();
  };
};

// Middleware para manejo de errores 404 con análisis de seguridad
export const smartNotFoundHandler = (req, res) => {
  const realIP = autoBanSystem.getRealIP(req);

  // Log request a ruta inexistente
  console.log(
    `🔍 [404] REQUEST: ${req.method} ${req.originalUrl} desde ${realIP}`
  );

  // Analizar si es un patrón sospechoso
  const isSuspicious = autoBanSystem.botPatterns.some((pattern) =>
    pattern.test(req.originalUrl)
  );

  if (isSuspicious) {
    console.log(`🚨 [404] RUTA SOSPECHOSA: ${req.originalUrl} desde ${realIP}`);
  }

  res.status(404).json({
    success: false,
    message: `Ruta ${req.method} ${req.originalUrl} no encontrada`,
    availableEndpoints: [
      "GET /",
      "GET /api/health",
      "GET /api/info",
      "GET|POST /api/zoosanitarycertificate",
      "GET /api/externalverificationsheet",
      "GET /api/slaughterrecord",
      "GET /api/internalverificationsheet",
      "GET /api/shippingsheet",
      "GET|POST|PUT|DELETE /api/camal",
      "GET|POST|PUT|DELETE /api/introducer",
      "GET|POST|PUT|DELETE /api/invoice",
      "GET|POST|PUT|DELETE /api/slaughter-process",
      "GET|POST|PUT|DELETE /api/tariff-config",
      "GET /admin/bans - Estadísticas de seguridad",
      "POST /admin/unban/:ip - Desbanear IP",
    ],
    timestamp: new Date().toISOString(),
  });
};

// Rutas de administración del sistema de baneos
export const createBanAdminRoutes = (app) => {
  // Ruta para ver estadísticas de baneos
  app.get("/api/admin/bans", auth, async (req, res) => {
    try {
      const stats = autoBanSystem.getStats();
      res.json({
        success: true,
        data: stats,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error("❌ [AutoBan] Error obteniendo estadísticas:", error);
      res.status(500).json({
        success: false,
        message: "Error interno obteniendo estadísticas",
      });
    }
  });

  // Ruta para dashboard de seguridad
  app.get("/api/admin/security-dashboard", auth, async (req, res) => {
    try {
      const dashboard = autoBanSystem.getDashboard();
      res.json({
        success: true,
        dashboard,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error("❌ [AutoBan] Error obteniendo dashboard:", error);
      res.status(500).json({
        success: false,
        message: "Error interno obteniendo dashboard",
      });
    }
  });

  // Ruta para desbanear una IP específica
  app.post("/api/admin/unban/:ip", auth, async (req, res) => {
    const ip = req.params.ip;
    const adminIP = autoBanSystem.getRealIP(req);

    try {
      const success = autoBanSystem.unbanIP(ip);

      if (success) {
        console.log(`👤 [AutoBan] Admin desde ${adminIP} desbaneó IP: ${ip}`);

        autoBanSystem.logSecurity("ADMIN_UNBAN", {
          targetIP: ip,
          adminIP: adminIP,
          timestamp: new Date().toISOString(),
        });

        res.json({
          success: true,
          message: `IP ${ip} desbaneada exitosamente`,
          timestamp: new Date().toISOString(),
        });
      } else {
        res.status(404).json({
          success: false,
          message: `IP ${ip} no estaba baneada`,
          timestamp: new Date().toISOString(),
        });
      }
    } catch (error) {
      console.error("❌ [AutoBan] Error desbaneando IP:", error);
      res.status(500).json({
        success: false,
        message: "Error interno desbaneando IP",
      });
    }
  });

  // Ruta para agregar IP a whitelist
  app.post("/api/admin/whitelist/:ip", auth, async (req, res) => {
    const ip = req.params.ip;
    const adminIP = autoBanSystem.getRealIP(req);

    try {
      autoBanSystem.addToWhitelist(ip);

      console.log(
        `👤 [AutoBan] Admin desde ${adminIP} agregó a whitelist: ${ip}`
      );

      autoBanSystem.logSecurity("ADMIN_WHITELIST", {
        targetIP: ip,
        adminIP: adminIP,
        timestamp: new Date().toISOString(),
      });

      res.json({
        success: true,
        message: `IP ${ip} agregada a whitelist exitosamente`,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      console.error("❌ [AutoBan] Error agregando a whitelist:", error);
      res.status(500).json({
        success: false,
        message: "Error interno agregando a whitelist",
      });
    }
  });

  // Ruta para banear manualmente una IP
  app.post("/api/admin/ban/:ip", auth, async (req, res) => {
    const ip = req.params.ip;
    const reason = req.body.reason || "Ban manual por administrador";
    const adminIP = autoBanSystem.getRealIP(req);

    try {
      const success = autoBanSystem.banIP(ip, reason, {
        type: "manual",
        adminIP: adminIP,
      });

      if (success) {
        console.log(
          `👤 [AutoBan] Admin desde ${adminIP} baneó manualmente: ${ip}`
        );

        res.json({
          success: true,
          message: `IP ${ip} baneada exitosamente`,
          reason: reason,
          timestamp: new Date().toISOString(),
        });
      } else {
        res.status(400).json({
          success: false,
          message: `IP ${ip} ya estaba baneada o está en whitelist`,
          timestamp: new Date().toISOString(),
        });
      }
    } catch (error) {
      console.error("❌ [AutoBan] Error baneando IP manualmente:", error);
      res.status(500).json({
        success: false,
        message: "Error interno baneando IP",
      });
    }
  });
};

// Función para obtener la instancia del sistema (para uso externo)
export const getAutoBanSystem = () => autoBanSystem;

// Función de limpieza para cierre graceful
export const cleanupAutoBanSystem = () => {
  autoBanSystem.destroy();
};
