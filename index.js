// =============================================================================
// index.js - Punto de entrada principal de la aplicación
// =============================================================================
import dotenv from 'dotenv';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';

// Configuración de entorno
dotenv.config();

// Importaciones de configuración
import { connectToDatabase, getDatabaseStats } from './src/config/database.mongo.js';
import { initializeLogger, logger } from './src/config/logger.js';

// Importaciones de módulos principales
import { AuthLifecycle } from './src/security/authentication/authentication.index.js';

// =============================================================================
// CONFIGURACIÓN INICIAL
// =============================================================================

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// =============================================================================
// MIDDLEWARES GLOBALES
// =============================================================================

// Seguridad básica
app.use(helmet({
  contentSecurityPolicy: NODE_ENV === 'production',
  crossOriginEmbedderPolicy: false
}));

// Compresión
app.use(compression());

// CORS
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:4200',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: process.env.RATE_LIMIT_MAX || 100, // límite por IP
  message: {
    error: 'Too many requests',
    message: 'Has excedido el límite de requests. Intenta de nuevo en 15 minutos.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Logging
if (NODE_ENV !== 'test') {
  app.use(morgan('combined', {
    stream: { write: message => logger.info(message.trim()) }
  }));
}

// =============================================================================
// HEALTH CHECK ENDPOINTS
// =============================================================================

app.get('/health', (req, res) => {
  const dbStats = getDatabaseStats();
  
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV,
    version: process.env.npm_package_version || '1.0.0',
    database: {
      status: dbStats.isConnected ? 'connected' : 'disconnected',
      ...dbStats
    },
    memory: process.memoryUsage(),
    nodejs: process.version
  });
});

app.get('/health/ready', async (req, res) => {
  try {
    const dbStats = getDatabaseStats();
    
    if (!dbStats.isConnected) {
      throw new Error('Database not connected');
    }

    res.status(200).json({
      status: 'READY',
      services: {
        database: 'UP',
        authentication: 'UP'
      }
    });
  } catch (error) {
    res.status(503).json({
      status: 'NOT_READY',
      error: error.message
    });
  }
});

// =============================================================================
// API ROUTES (PLACEHOLDER)
// =============================================================================

// API base
app.get('/api', (req, res) => {
  res.json({
    message: 'Life Business Platform API',
    version: '1.0.0',
    documentation: '/api/docs',
    endpoints: {
      health: '/health',
      auth: '/api/auth',
      businesses: '/api/businesses',
      users: '/api/users'
    }
  });
});

// TODO: Implementar rutas de módulos
// app.use('/api/auth', authRoutes);
// app.use('/api/businesses', businessRoutes);
// app.use('/api/users', userRoutes);

// =============================================================================
// ERROR HANDLING
// =============================================================================

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `Cannot ${req.method} ${req.originalUrl}`,
    availableEndpoints: ['/health', '/api']
  });
});

// Error Handler Global
app.use((error, req, res, next) => {
  logger.error('Error no manejado:', {
    error: error.message,
    stack: error.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  const status = error.statusCode || error.status || 500;
  const message = NODE_ENV === 'production' 
    ? 'Internal Server Error' 
    : error.message;

  res.status(status).json({
    error: 'Server Error',
    message,
    ...(NODE_ENV !== 'production' && { 
      stack: error.stack,
      details: error 
    })
  });
});

// =============================================================================
// FUNCIONES DE INICIALIZACIÓN
// =============================================================================

/**
 * Inicializar todos los servicios de la aplicación
 */
async function initializeApplication() {
  try {
    logger.info('🚀 Iniciando Life Business Platform...');

    // 1. Inicializar logger
    await initializeLogger();
    logger.info('✅ Logger inicializado');

    // 2. Conectar a la base de datos
    await connectToDatabase();
    logger.info('✅ Base de datos conectada');

    // 3. Inicializar módulo de autenticación
    await AuthLifecycle.initialize();
    logger.info('✅ Módulo de autenticación inicializado');

    // TODO: Inicializar otros módulos
    // await BusinessModule.initialize();
    // await NotificationModule.initialize();
    // await TranslationModule.initialize();

    logger.info('🎉 Aplicación inicializada exitosamente');
    return true;

  } catch (error) {
    logger.error('❌ Error inicializando aplicación:', error);
    throw error;
  }
}

/**
 * Manejar el cierre elegante de la aplicación
 */
async function gracefulShutdown(signal) {
  logger.info(`📴 Recibida señal ${signal}. Cerrando aplicación...`);

  try {
    // Cerrar servidor HTTP
    if (server) {
      await new Promise((resolve) => {
        server.close(resolve);
      });
      logger.info('✅ Servidor HTTP cerrado');
    }

    // TODO: Cerrar otros servicios
    // await AuthLifecycle.shutdown();
    // await databaseManager.disconnect();

    logger.info('✅ Aplicación cerrada exitosamente');
    process.exit(0);

  } catch (error) {
    logger.error('❌ Error durante el cierre:', error);
    process.exit(1);
  }
}

// =============================================================================
// INICIALIZACIÓN Y ARRANQUE
// =============================================================================

let server;

async function startServer() {
  try {
    // Inicializar aplicación
    await initializeApplication();

    // Iniciar servidor
    server = app.listen(PORT, () => {
      logger.info(`🌟 Servidor iniciado exitosamente`);
      logger.info(`📍 Entorno: ${NODE_ENV}`);
      logger.info(`🔗 URL: http://localhost:${PORT}`);
      logger.info(`🏥 Health Check: http://localhost:${PORT}/health`);
      logger.info(`📊 API Docs: http://localhost:${PORT}/api`);
      
      // Mostrar estadísticas de la base de datos
      const dbStats = getDatabaseStats();
      logger.info('💾 Base de datos:', dbStats);
    });

    // Configurar manejo de errores del servidor
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        logger.error(`❌ Puerto ${PORT} ya está en uso`);
      } else {
        logger.error('❌ Error del servidor:', error);
      }
      process.exit(1);
    });

  } catch (error) {
    logger.error('❌ Error crítico iniciando servidor:', error);
    process.exit(1);
  }
}

// Manejo de señales de cierre
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Manejo de excepciones no capturadas
process.on('uncaughtException', (error) => {
  logger.error('❌ Excepción no capturada:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('❌ Promise rechazada no manejada:', { reason, promise });
  process.exit(1);
});

// =============================================================================
// ARRANQUE PRINCIPAL
// =============================================================================

// Solo iniciar servidor si este archivo es ejecutado directamente
if (import.meta.url === `file://${process.argv[1]}`) {
  startServer();
}

// Exportar para testing
export default app;
export { startServer, gracefulShutdown };