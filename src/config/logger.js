// =============================================================================
// src/config/logger.js - Configuración de Winston Logger
// =============================================================================
import winston from 'winston';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuración de niveles de log personalizados
const customLevels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

const customColors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'blue',
};

winston.addColors(customColors);

// Formato personalizado para logs
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

// Formato para consola (desarrollo)
const consoleFormat = winston.format.combine(
  winston.format.colorize({ all: true }),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
    return `${timestamp} [${level}]: ${message} ${metaStr}`;
  })
);

// Configuración de transports
const createTransports = () => {
  const transports = [];

  // Siempre agregar consola
  transports.push(
    new winston.transports.Console({
      level: process.env.LOG_LEVEL || 'info',
      format: process.env.NODE_ENV === 'production' ? logFormat : consoleFormat,
      handleExceptions: true,
      handleRejections: true,
      silent: process.env.NODE_ENV === 'test'
    })
  );

  // En producción, agregar archivos de log
  if (process.env.NODE_ENV === 'production') {
    const logDir = process.env.LOG_DIR || path.join(process.cwd(), 'logs');

    // Log de errores
    transports.push(
      new winston.transports.File({
        filename: path.join(logDir, 'error.log'),
        level: 'error',
        format: logFormat,
        maxsize: 10 * 1024 * 1024, // 10MB
        maxFiles: 5,
        tailable: true
      })
    );

    // Log combinado
    transports.push(
      new winston.transports.File({
        filename: path.join(logDir, 'combined.log'),
        format: logFormat,
        maxsize: 10 * 1024 * 1024, // 10MB
        maxFiles: 10,
        tailable: true
      })
    );

    // Log de HTTP requests
    transports.push(
      new winston.transports.File({
        filename: path.join(logDir, 'http.log'),
        level: 'http',
        format: logFormat,
        maxsize: 5 * 1024 * 1024, // 5MB
        maxFiles: 5,
        tailable: true
      })
    );
  }

  return transports;
};

// Crear instancia del logger
export const logger = winston.createLogger({
  levels: customLevels,
  level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
  format: logFormat,
  transports: createTransports(),
  exitOnError: false
});

// Función para inicializar el logger
export const initializeLogger = async () => {
  try {
    // Crear directorio de logs si no existe (solo en producción)
    if (process.env.NODE_ENV === 'production') {
      const fs = await import('fs');
      const logDir = process.env.LOG_DIR || path.join(process.cwd(), 'logs');
      
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
      }
    }

    logger.info('🔧 Logger inicializado correctamente', {
      level: logger.level,
      transports: logger.transports.length,
      environment: process.env.NODE_ENV
    });

    return true;
  } catch (error) {
    console.error('❌ Error inicializando logger:', error);
    throw error;
  }
};

// Función helper para logging con contexto
export const logWithContext = (level, message, context = {}) => {
  logger.log(level, message, {
    timestamp: new Date().toISOString(),
    pid: process.pid,
    ...context
  });
};

// Función para logging de errores con stack trace
export const logError = (error, context = {}) => {
  logger.error(error.message, {
    error: {
      name: error.name,
      message: error.message,
      stack: error.stack,
      code: error.code,
      statusCode: error.statusCode
    },
    ...context
  });
};

// Función para logging de requests HTTP
export const logRequest = (req, res, responseTime) => {
  logger.http('HTTP Request', {
    method: req.method,
    url: req.url,
    statusCode: res.statusCode,
    responseTime: `${responseTime}ms`,
    userAgent: req.get('User-Agent'),
    ip: req.ip || req.connection?.remoteAddress,
    contentLength: res.get('Content-Length') || 0
  });
};

// Función para logging de métricas de performance
export const logPerformance = (operation, duration, metadata = {}) => {
  logger.info(`Performance: ${operation}`, {
    operation,
    duration: `${duration}ms`,
    performance: true,
    ...metadata
  });
};

// Función para logging de seguridad
export const logSecurity = (event, details = {}) => {
  logger.warn(`Security Event: ${event}`, {
    security: true,
    event,
    timestamp: new Date().toISOString(),
    ...details
  });
};

// Stream para Morgan (HTTP logging)
export const morganStream = {
  write: (message) => {
    logger.http(message.trim());
  }
};

// Crear child logger con contexto específico
export const createChildLogger = (context) => {
  return logger.child(context);
};

// Función para logging de debugging (solo en desarrollo)
export const debugLog = (message, data = {}) => {
  if (process.env.NODE_ENV !== 'production') {
    logger.debug(message, data);
  }
};

// Exportar instancia por defecto
export default logger;