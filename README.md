Arquitectura de Implementación Completa
Prioridades de Implementación (Revisadas con Código Existente)
Fase 1 (MVP - Octubre) - CRÍTICA

1. User Schema - Autenticación segura con preferencias de idioma
2. User Session Schema - Gestión de sesiones con device fingerprinting
3. Business Schema - Información empresarial multiidioma
4. Address Schema - Geolocalización precisa
5. Role Schema - Control de acceso básico (RBAC)
6. Business Category Schema - Clasificación multiidioma
7. Translation Cache Schema - Optimización de traducciones
8. Audit Log Schema - Sistema de auditoría por capas
   Fase 2 (Post-MVP) - IMPORTANTE
9. Permission Schema - Control granular de accesos
10. News Article Schema - Contenido empresarial multiidioma
11. User Review Schema - Sistema de reseñas traducibles
12. Media Schema - Gestión de archivos multimedia
13. Notification Template Schema - Notificaciones multiidioma
14. User Language Preference Schema - Configuración avanzada
    Fase 3 (Características Avanzadas)
15. Business Service Schema - Servicios detallados
16. Geographic Zone Schema - Áreas de cobertura
17. Location Restriction Schema - Control geográfico
18. Security Activity Log Schema - Integración con AutoBanSystem
19. File Upload Schema - Gestión segura de archivos
20. Transaction Log Schema - Trazabilidad financiera

21. Arquitectura de Documentos
    +---config
    | database.mongo.js
    |  
    +---middlewares
    +---modules
    | +---business
    | | | business.index.js
    | | |
    | | +---controllers
    | | +---models
    | | | address.scheme.js
    | | | business.scheme.js
    | | | business_category.scheme.js
    | | |
    | | +---repositories
    | | \---routes
    | \---core
    | | core.index.js
    | |
    | +---controllers
    | +---models
    | | base.scheme.js
    | | multi_language_pattern.scheme.js
    | |
    | +---repositories
    | | base.repository.js
    | |
    | \---routes
    +---notifications
    | | notifications.index.js
    | |
    | +---controllers
    | +---models
    | +---repositories
    | \---routes
    +---security
    | +---audit
    | | | audit.index.js
    | | |
    | | +---controllers
    | | +---models
    | | | AuditLog.js
    | | |
    | | +---repositories
    | | | audit.repository.js
    | | |
    | | \---routes
    | +---authentication
    | | | authentication.index.js
    | | |
    | | +---controllers
    | | +---models
    | | | role.scheme.js
    | | | user.scheme.js
    | | | user_session.scheme.js
    | | |
    | | +---repositories
    | | \---routes
    | \---securityservice
    | auto_ban.js
    | auto_ban.system.js
    |
    +---system
    | | system.index.js
    | |
    | +---controllers
    | +---middlewares
    | | files.middleware.js
    | |
    | +---models
    | | file_upload.scheme.js
    | | security_activity_log.scheme.js
    | | translation_cache.scheme.js
    | |
    | +---repositories
    | \---routes
    \---utils
    scheme.helpers.js
    transsaccion.helper.js

22. Middleware Stack Integrado
    // Orden de middlewares recomendado
    app.use(helmet()); // Seguridad básica
    app.use(createIntegratedSecurityMiddleware()); // Tu AutoBan + Device fingerprinting
    app.use(createSmartRateLimit()); // Tu rate limiting existente
    app.use(sessionMiddleware()); // Validación de sesiones
    app.use(deviceFingerprintMiddleware()); // Validación de device
    app.use(auditMiddleware()); // Tu auditoría existente
23. Servicios de Seguridad Unificados
    // src/services/security/
    export class SecurityService {
    constructor() {
    this.autoBanSystem = getAutoBanSystem(); // Tu código existente
    this.sessionManager = new SessionManager(); // Nuevo
    this.deviceTracker = new DeviceTracker(); // Nuevo
    }

// Análisis completo de seguridad
async analyzeSecurityContext(req) {
const banAnalysis = this.autoBanSystem.analyzeRequest(req);
const deviceAnalysis = this.deviceTracker.analyzeFingerprint(req);
const sessionAnalysis = await this.sessionManager.validateSession(req);

    return {
      overallRisk: this.calculateRiskScore(banAnalysis, deviceAnalysis, sessionAnalysis),
      recommendations: this.getSecurityRecommendations(banAnalysis, deviceAnalysis),
      actions: this.getAutomaticActions(banAnalysis, deviceAnalysis)
    };

}
}
Beneficios de la Arquitectura Completa
✅ Para Propietarios de Empresas
• Escriben en su idioma nativo - sistema de traducción automática
• Expansión automática a mercados internacionales
• Sin trabajo manual de traducción o configuración técnica
• Mayor alcance de clientes potenciales
• Seguridad transparente - protección sin fricción
✅ Para Usuarios Finales
• Experiencia en idioma nativo - traducción automática de contenido
• Mejor comprensión de servicios y ofertas
• Mayor confianza y engagement con las empresas
• Búsquedas más efectivas por proximidad y idioma
• Seguridad invisible - protección sin interrupciones
✅ Para la Plataforma
• Ventaja competitiva única - traducción automática + geolocalización
• Mayor retención de usuarios por experiencia personalizada
• Justifica precios premium por funcionalidades avanzadas
• Escalabilidad internacional automática
• Seguridad empresarial - protección contra amenazas automática
✅ Para Desarrolladores
• Código reutilizable - GenericRepository para todo
• Auditoría automática - sin código adicional
• Seguridad integrada - AutoBan + Device fingerprinting
• Transacciones inteligentes - fallback automático
• Logging completo - análisis y debugging facilitado
Consideraciones Técnicas Finales
Rendimiento y Escalabilidad
// Estrategia de cache multicapa
interface CacheStrategy {
// Nivel 1: Redis para sesiones activas
sessionCache: {
ttl: '30m',
maxSize: '100MB',
strategy: 'LRU'
};

// Nivel 2: MongoDB aggregation cache
translationCache: {
ttl: '24h',
hitRate: '95%',
strategy: 'fuzzy-match'
};

// Nivel 3: CDN para contenido estático
staticContentCache: {
ttl: '7d',
locations: 'global',
strategy: 'geographic'
};
}
Monitoreo y Alertas
// Dashboard de métricas integrado
interface MonitoringDashboard {
security: {
bannedIPs: number;
suspiciousActivity: number;
sessionHijackingAttempts: number;
deviceFingerprintMismatches: number;
};

performance: {
translationCacheHitRate: number;
averageResponseTime: number;
transactionSuccessRate: number;
auditLogSize: number;
};

business: {
activeBusinesses: number;
dailyTranslations: number;
userSessions: number;
geographicDistribution: Map<string, number>;
};
}
Compliance y Regulaciones
// Cumplimiento automático de regulaciones
interface ComplianceFramework {
GDPR: {
dataRetention: '7 years',
rightToForgotten: 'automated',
dataPortability: 'json-export',
consentTracking: 'audit-log-integrated',
dataMinimization: 'field-level-encryption'
};

SOX: {
auditTrail: 'complete-versioning',
accessControls: 'rbac-abac-integrated',
dataIntegrity: 'hash-verification',
changeManagement: 'approval-workflows'
};

PCI_DSS: {
tokenization: 'payment-data-only',
encryption: 'at-rest-and-transit',
accessLogging: 'all-card-data-access',
networkSegmentation: 'firewall-rules'
};
}
Arquitectura de Deployment
// Configuración de producción recomendada
interface ProductionArchitecture {
database: {
primary: 'MongoDB Atlas M40+ (Replica Set)',
secondary: 'Read replicas for geographic distribution',
backup: 'Point-in-time recovery + daily snapshots',
sharding: 'By geographic region (businessLocation.country)'
};

application: {
containers: 'Docker + Kubernetes',
scaling: 'Horizontal auto-scaling based on CPU/Memory',
loadBalancer: 'Geographic-aware routing',
cdn: 'CloudFlare for static content + translated cache'
};

security: {
waf: 'Web Application Firewall + AutoBan integration',
ddos: 'DDoS protection at edge',
ssl: 'TLS 1.3 with HSTS',
secrets: 'HashiCorp Vault or AWS Secrets Manager'
};

monitoring: {
apm: 'Application Performance Monitoring',
logs: 'Centralized logging with ELK stack',
metrics: 'Prometheus + Grafana dashboards',
alerts: 'PagerDuty integration for critical issues'
};
}
Roadmap de Desarrollo Técnico
Sprint 1-2 (Semanas 1-4): Fundación Sólida
// Objetivos técnicos específicos
const Sprint1Goals = {
coreSchemas: [
'User', 'UserSession', 'Business', 'Address', 'Role'
],

securityIntegration: {
task: 'Integrar AutoBanSystem con SessionManagement',
deliverable: 'Middleware de seguridad unificado',
testing: 'Pruebas de penetración básicas'
},

auditSystem: {
task: 'Implementar sistema de auditoría por capas',
deliverable: 'GenericRepository con auditoría automática',
testing: 'Verificar reconstrucción histórica'
}
};
Sprint 3-4 (Semanas 5-8): Funcionalidades Core
const Sprint2Goals = {
translationSystem: {
task: 'Sistema de traducción con OpenAI',
deliverable: 'Traducción automática de contenido empresarial',
caching: 'Redis cache con 95% hit rate objetivo'
},

geolocation: {
task: 'Búsqueda por proximidad',
deliverable: 'API de geolocalización con filtros',
performance: 'Sub-100ms response time'
},

fileManagement: {
task: 'Integrar sistema de archivos con auditoría',
deliverable: 'Upload optimizado con tracking completo',
storage: 'CDN integration + virus scanning'
}
};
Sprint 5-6 (Semanas 9-10): Optimización y Testing
const Sprint3Goals = {
performance: {
task: 'Optimización de queries y caching',
deliverable: 'Sistema escalable para 10K+ usuarios concurrentes',
metrics: 'Response time < 200ms para 95% de requests'
},

security: {
task: 'Penetration testing y hardening',
deliverable: 'Sistema resistente a ataques comunes',
certification: 'Security audit completo'
},

monitoring: {
task: 'Dashboard completo de métricas',
deliverable: 'Monitoreo en tiempo real de todas las métricas',
alerting: 'Alertas automáticas configuradas'
}
};
Estimaciones Realistas con tu Experiencia
Factores de Aceleración (Con tu código existente)
const AccelerationFactors = {
auditSystem: {
timeSaved: '70%', // Ya tienes el sistema implementado
reason: 'audit.repository.js + generic.repository.js ya funcionan'
},

securitySystem: {
timeSaved: '60%', // AutoBanSystem ya está implementado
reason: 'autoBanSystem.js + middlewares ya funcionan'
},

fileManagement: {
timeSaved: '50%', // files.middleware.js ya optimiza imágenes
reason: 'Sharp + WebP optimization ya implementado'
},

transactionHandling: {
timeSaved: '80%', // TransactionHelper ya maneja fallbacks
reason: 'transaction.helper.js ya resuelve MongoDB standalone'
}
};
Timeline Realista Ajustado
const RealisticTimeline = {
totalEstimate: '8-10 semanas para MVP completo',

breakdown: {
week1_2: 'Schemas + Database setup (tu experiencia acelera esto)',
week3_4: 'API endpoints + Business logic',
week5_6: 'Frontend Angular + PrimeNG integration',
week7_8: 'Translation system + Geographic search',
week9_10: 'Testing + Security hardening + Deployment'
},

criticalPath: [
'Translation system implementation',
'Geographic search optimization',
'Frontend-backend integration',
'Security testing'
],

riskMitigation: {
translationAPI: 'Fallback a Google Translate si OpenAI falla',
geographic: 'Usar MongoDB geospatial queries (bien documentado)',
frontend: 'PrimeNG components aceleran desarrollo',
security: 'Tu AutoBanSystem ya cubre 80% de casos'
}
};
Recomendaciones Finales
🎯 Enfoque Estratégico para Octubre

1. Usar tu código existente como base - ya tienes 60% del backend
2. Priorizar funcionalidades core - geolocalización + traducción básica
3. MVP lean pero profesional - calidad empresarial desde el inicio
4. Iteración rápida - releases semanales para feedback
   🔧 Stack Tecnológico Definitivo
   const TechStack = {
   backend: {
   framework: 'Express.js + TypeScript',
   database: 'MongoDB (con tu TransactionHelper)',
   caching: 'Redis (sesiones + traducciones)',
   ai: 'OpenAI GPT-4 (traducción)',
   storage: 'AWS S3 + CloudFront (archivos)'
   },

frontend: {
framework: 'Angular 17+',
ui: 'PrimeNG (Genesis theme)',
maps: 'Google Maps API',
mobile: 'Capacitor (post-MVP)'
},

security: {
session: 'Cookie-based (tu implementación)',
ban: 'AutoBanSystem (tu código)',
audit: 'Audit por capas (tu código)',
device: 'Device fingerprinting (nuevo)'
}
};
🚀 Plan de Acción Inmediato

1. Esta semana: Setup del proyecto + schemas básicos
2. Próxima semana: Integrar tu código existente + nuevos schemas
3. Tercera semana: APIs + frontend básico
4. Cuarta semana: Sistema de traducción
5. Últimas semanas: Testing + deployment
   💡 Consideraciones de Negocio
   • Modelo freemium: Básico gratis, premium con más traducciones
   • Métricas clave: Empresas activas, traducciones/día, búsquedas geográficas
   • Diferenciación: Único en el mercado con traducción automática + geo
   • Escalabilidad: Arquitectura preparada para 100K+ empresas
   ¿Estás listo para empezar? Tu código existente te da una ventaja ENORME. Con la experiencia que demuestras, este proyecto definitivamente es viable para octubre. 🎯
   ¡Créa el nuevo proyecto en Claude y continuemos con la implementación específica!# Arquitectura MongoDB - Plataforma de Geolocalización de Empresas con Sistema Multiidioma
   Esquemas de Autenticación y Autorización
6. User Schema (Con Seguridad Basada en Sesiones)
   Propósito: Usuarios del sistema (clientes, propietarios de empresas, administradores) Responsabilidades clave:
   • Autenticación y gestión de perfiles de usuario
   • Integración OAuth (Google, Facebook, etc.)
   • Gestión de sesiones seguras (NO tokens en requests)
   • Estado de cuenta y verificación
   • Preferencias personales y configuraciones
   • Enlaces a propiedad de empresas y roles
   Campos clave con seguridad por sesiones:
   interface UserSchema extends BaseSchema {
   userId: ObjectId;
   email: string;
   passwordHash: string; // Hash seguro (bcrypt/argon2)

// Información de perfil
profile: {
firstName: string;
lastName: string;
avatar?: string;
dateOfBirth?: Date;
phone?: string;
};

// OAuth providers (sin tokens)
oauthProviders: {
google?: {
providerId: string; // Solo ID, NO tokens
email: string;
isVerified: boolean;
};
facebook?: {
providerId: string; // Solo ID, NO tokens
email: string;
isVerified: boolean;
};
apple?: {
providerId: string; // Solo ID, NO tokens
email: string;
isVerified: boolean;
};
};

// Roles y permisos
roles: ObjectId[];

// Estado de cuenta
isActive: boolean;
isEmailVerified: boolean;
emailVerificationToken?: string; // Solo para verificación temporal
emailVerificationExpires?: Date;

// Seguridad adicional
passwordResetToken?: string; // Solo para reset temporal
passwordResetExpires?: Date;
lastLoginAt?: Date;
loginAttempts: number;
lockUntil?: Date;

// Preferencias
preferredLanguage: string;
timezone: string;

// NO incluir: accessTokens, refreshTokens, sessionTokens
// Estos se manejan en UserSession schema separado
} 2. Role Schema
Propósito: Definir roles del sistema y permisos Responsabilidades clave:
• Definiciones de roles (admin, business_owner, customer, moderator)
• Asignaciones de permisos
• Estructura jerárquica de roles
• Restricciones de roles específicas por empresa
• Campos clave: roleId, roleName, description, permissions, hierarchy, isSystemRole, companyRestrictions 3. Permission Schema
Propósito: Permisos granulares para acciones del sistema Responsabilidades clave:
• Definiciones de acciones (create, read, update, delete)
• Permisos específicos por recurso
• Alcances de permisos geográficos
• Restricciones de permisos basadas en tiempo
• Campos clave: permissionId, permissionName, resource, actions, geographicScope, timeRestrictions
Gestión de Empresas 4. Business Schema (Multiidioma)
Propósito: Entidades de negocio e información principal Responsabilidades clave:
• Perfil y detalles del negocio (multiidioma)
• Estado de verificación y documentación
• Horarios de operación y programaciones
• Categorías y etiquetas de negocio
• Estructura de propiedad y gestión
• Ubicación geográfica y áreas de servicio
Campos multiidioma:
interface BusinessSchema {
businessId: ObjectId;
businessName: MultiLanguageContent;
description: MultiLanguageContent;
shortDescription: MultiLanguageContent;
services: MultiLanguageContent[];
specializations: MultiLanguageContent[];
// Campos no traducibles
ownerId: ObjectId;
verificationStatus: string;
operatingHours: BusinessHoursSchema;
location: AddressSchema;
categories: ObjectId[];
createdAt: Date;
updatedAt: Date;
} 5. Business Category Schema (Multiidioma)
Propósito: Clasificar y organizar empresas Responsabilidades clave:
• Estructura jerárquica de categorías
• Clasificaciones de industria
• Definiciones de tipos de servicio
• Optimización de búsqueda y filtrado
• Campos clave: categoryId, categoryName (multiidioma), parentCategory, industryCode, description (multiidioma), isActive 6. Business Service Schema (Multiidioma)
Propósito: Servicios ofrecidos por empresas Responsabilidades clave:
• Descripciones de servicios y precios
• Disponibilidad y programación
• Cobertura geográfica de servicios
• Categorías y etiquetas de servicios
• Campos clave: serviceId, serviceName (multiidioma), description (multiidioma), pricing, availability, serviceArea
Gestión Geográfica y Ubicación 7. Address Schema
Propósito: Información de direcciones estandarizada Responsabilidades clave:
• Formato completo de direcciones
• Integración de coordenadas geográficas
• Validación y normalización de direcciones
• Soporte de direcciones multiidioma
• Campos clave: addressId, streetAddress, city, state, country, postalCode, coordinates, formattedAddress 8. Geographic Zone Schema (Multiidioma)
Propósito: Definir límites geográficos y regiones Responsabilidades clave:
• Definiciones de ciudad, estado, país
• Zonas de servicio personalizadas
• Límites administrativos
• Información de zona horaria y configuración regional
• Campos clave: zoneId, zoneName (multiidioma), zoneType, boundaries, timezone, parentZoneId 9. Location Restriction Schema
Propósito: Control de acceso geográfico Responsabilidades clave:
• Filtrado de ubicación basado en IP
• Restricciones de país/región
• Limitaciones de área de servicio
• Cumplimiento de regulaciones locales
• Campos clave: restrictionId, restrictionType, allowedCountries, blockedCountries, ipRanges, isActive
Gestión de Contenido 10. News Article Schema (Multiidioma)
Propósito: Noticias y anuncios de empresas Responsabilidades clave:
• Contenido y metadatos de artículos
• Programación de publicación
• Targeting geográfico
• Clasificación por categorías
• Adjuntos multimedia
Campos multiidioma:
interface NewsArticleSchema {
articleId: ObjectId;
title: MultiLanguageContent;
content: MultiLanguageContent;
summary: MultiLanguageContent;
tags: MultiLanguageContent[];
// Campos no traducibles
authorId: ObjectId;
businessId: ObjectId;
publishDate: Date;
geographicTargeting: ObjectId[];
mediaAttachments: ObjectId[];
isPublished: boolean;
} 11. Bulletin Schema (Multiidioma)
Propósito: Actualizaciones cortas de empresas Responsabilidades clave:
• Anuncios rápidos
• Notificaciones de eventos
• Actualizaciones de estado
• Distribución geográfica
• Campos clave: bulletinId, title (multiidioma), content (multiidioma), businessId, expiryDate, targetAreas 12. Media Schema
Propósito: Gestión de archivos y multimedia Responsabilidades clave:
• Almacenamiento de imágenes, videos, documentos
• Optimización y compresión de medios
• Control de acceso y permisos
• Integración con CDN
• Campos clave: mediaId, fileName, fileType, fileSize, url, thumbnailUrl, metadata, uploadedBy
Interacción de Usuarios 13. User Review Schema (Multiidioma)
Propósito: Reseñas y calificaciones de empresas Responsabilidades clave:
• Contenido de reseñas y calificaciones
• Verificación y moderación
• Gestión de respuestas
• Cálculos de calificación agregada
Campos multiidioma:
interface UserReviewSchema {
reviewId: ObjectId;
reviewTitle: MultiLanguageContent;
reviewContent: MultiLanguageContent;
// Campos no traducibles
userId: ObjectId;
businessId: ObjectId;
rating: number;
isVerified: boolean;
reviewDate: Date;
helpfulVotes: number;
} 14. User Favorite Schema
Propósito: Empresas guardadas y preferencias de usuario Responsabilidades clave:
• Listas de favoritos y colecciones
• Recomendaciones personalizadas
• Historial de búsqueda y patrones
• Preferencias de notificación
• Campos clave: favoriteId, userId, businessId, collectionName, addedDate, notes 15. Search History Schema
Propósito: Rastrear y optimizar búsquedas de usuario Responsabilidades clave:
• Registro de consultas de búsqueda
• Análisis de rendimiento
• Datos de personalización
• Tendencias de búsqueda populares
• Campos clave: searchId, userId, searchQuery, searchFilters, resultsCount, clickedResults, searchDate
Configuración del Sistema 16. System Configuration Schema
Propósito: Configuraciones globales de la aplicación Responsabilidades clave:
• Flags de características y toggles
• Parámetros de todo el sistema
• Límites de velocidad de API
• Modos de mantenimiento
• Campos clave: configId, configKey, configValue, configType, isActive, description 17. Notification Template Schema (Multiidioma)
Propósito: Notificaciones estandarizadas Responsabilidades clave:
• Plantillas de email/SMS
• Soporte multiidioma
• Marcadores de posición de contenido dinámico
• Preferencias de entrega
Campos multiidioma:
interface NotificationTemplateSchema {
templateId: ObjectId;
templateName: string;
subject: MultiLanguageContent;
content: MultiLanguageContent;
// Campos no traducibles
templateType: string;
channel: string[];
variables: string[];
isActive: boolean;
} 18. Audit Log Schema (Sistema de Versionado por Capas)
Propósito: Seguimiento completo de cambios con versionado histórico Responsabilidades clave:
• Registro de estados anteriores (no futuros)
• Versionado por capas para reconstrucción completa
• Soft delete tracking
• Seguimiento de eventos de seguridad
• Reportes de cumplimiento y recuperación de datos
interface AuditLogSchema {
auditId: ObjectId;

// Identificación del registro afectado
targetCollection: string; // 'users', 'businesses', etc.
targetDocumentId: ObjectId; // ID del documento modificado

// Información del cambio
changeType: 'create' | 'update' | 'delete' | 'restore';
previousValues: Record<string, any>; // ESTADO ANTERIOR (clave del sistema)
changedFields: string[]; // Campos que cambiaron

// Metadatos del cambio
changedBy: ObjectId; // Usuario que realizó el cambio
changedAt: Date; // Timestamp del cambio
changeReason?: string; // Razón del cambio (opcional)

// Información contextual
ipAddress: string;
userAgent: string;
sessionId?: string;

// Versionado
version: number; // Versión del documento después del cambio
previousVersion: number; // Versión antes del cambio

// Soft delete tracking
isDeleteAction: boolean; // True si es soft delete
deletedAt?: Date; // Fecha de soft delete

// Metadatos adicionales
applicationContext?: {
module: string; // Módulo de la app que hizo el cambio
action: string; // Acción específica (e.g., 'profile_update')
correlationId?: string; // Para rastrear operaciones relacionadas
};
}
Campos clave: auditId, targetCollection, targetDocumentId, changeType, previousValues, changedFields, changedBy, changedAt, version, isDeleteAction
Esquemas Especializados 19. Business Hours Schema
Propósito: Gestión compleja de horarios Responsabilidades clave:
• Horarios de operación regulares
• Horarios de vacaciones
• Horarios de eventos especiales
• Manejo de zonas horarias
• Campos clave: scheduleId, businessId, dayOfWeek, openTime, closeTime, isHoliday, specialEvents 20. Contact Information Schema
Propósito: Detalles de contacto multicanal Responsabilidades clave:
• Teléfono, email, redes sociales
• Preferencias de contacto
• Estado de verificación
• Historial de comunicación
• Campos clave: contactId, businessId, contactType, contactValue, isPrimary, isVerified, preferences
Sistema de Traducción Multiidioma
Patrón Base para Contenido Multiidioma
interface MultiLanguageContent {
original: {
language: string; // 'es', 'en', 'fr', etc.
text: string; // Contenido original
};
translations: {
[languageCode: string]: {
text: string;
translatedAt: Date;
translationMethod: 'ai' | 'manual' | 'auto';
confidence?: number; // Puntuación de confianza de IA
needsReview?: boolean; // Flag para revisión humana
};
};
lastUpdated: Date;
} 21. Translation Cache Schema
Propósito: Cache de traducciones para optimización Responsabilidades clave:
• Cache de traducciones exactas y difusas
• Reducción de costos de API
• Mejora de tiempos de respuesta
• Consistencia en traducciones repetidas
interface TranslationCacheSchema {
cacheId: ObjectId;
sourceText: string;
sourceLanguage: string;
targetLanguage: string;
translatedText: string;
translationService: 'openai' | 'google' | 'deepl';
confidence: number;
createdAt: Date;
usageCount: number; // Para traducciones populares
isVerified: boolean; // Verificado por humanos
textHash: string; // Para búsquedas rápidas
} 23. User Session Schema (Gestión Segura de Sesiones con Device Fingerprinting)
Propósito: Gestión de sesiones de usuario sin exponer tokens en requests Responsabilidades clave:
• Almacenamiento seguro de tokens de acceso
• Gestión de sesiones activas con device fingerprinting
• Control de sesiones concurrentes
• Invalidación automática de sesiones
• Seguimiento de actividad de sesión
• Detección de session hijacking
interface UserSessionSchema extends BaseSchema {
sessionId: ObjectId;
userId: ObjectId; // Referencia al usuario

// Tokens seguros (NUNCA se envían en requests)
accessToken: string; // Token de acceso (almacenado en servidor)
refreshToken: string; // Token de refresco (almacenado en servidor)

// Información de sesión
sessionToken: string; // Token de sesión (cookie httpOnly)

// Device Fingerprinting para seguridad
deviceFingerprint: string; // Huella única del dispositivo
originalFingerprint: string; // Fingerprint al crear sesión
fingerprintChanges: [{
newFingerprint: string;
changedAt: Date;
suspiciousChange: boolean;
validatedByUser?: boolean;
}];

// Metadatos de sesión
isActive: boolean;
createdAt: Date;
lastAccessedAt: Date;
expiresAt: Date;

// Información del cliente
ipAddress: string;
userAgent: string;
deviceInfo: {
browser: string;
os: string;
device: string;
isMobile: boolean;
screenResolution: string;
timezone: string;
};

// Información geográfica
location: {
country?: string;
city?: string;
coordinates?: [number, number]; // [longitude, latitude]
isVpnDetected?: boolean;
};

// OAuth session data (si aplica)
oauthProvider?: 'google' | 'facebook' | 'apple' | 'microsoft';
oauthSessionData?: {
accessToken: string; // OAuth token (servidor únicamente)
refreshToken?: string; // OAuth refresh (servidor únicamente)
expiresAt: Date;
scope: string[];
};

// Control de seguridad
isCompromised: boolean; // Flag si se detecta actividad sospechosa
invalidationReason?: string; // Razón de invalidación
suspiciousActivity: [{
activityType: 'device_change' | 'location_change' | 'unusual_access' | 'concurrent_session';
description: string;
timestamp: Date;
severity: 'low' | 'medium' | 'high';
resolved: boolean;
}];

// Configuración de sesión
rememberMe: boolean; // Sesión persistente
maxInactivityMinutes: number; // Timeout de inactividad
autoLogoutWarningShown?: Date; // Última vez que se mostró warning de auto-logout
} 24. Session Security Configuration Schema
Propósito: Configuración de seguridad para manejo de sesiones Responsabilidades clave:
• Políticas de expiración de sesiones
• Configuración de cookies seguras
• Reglas de invalidación automática
• Configuración de sesiones concurrentes
interface SessionSecurityConfigSchema extends BaseSchema {
configId: ObjectId;
configName: string;

// Configuración de cookies
cookieSettings: {
httpOnly: boolean; // Siempre true para seguridad
secure: boolean; // true en producción (HTTPS)
sameSite: 'strict' | 'lax' | 'none';
maxAge: number; // Tiempo de vida en segundos
domain?: string;
path: string;
};

// Configuración de tokens
tokenSettings: {
accessTokenTTL: number; // TTL en minutos
refreshTokenTTL: number; // TTL en días
sessionTokenTTL: number; // TTL en horas
tokenRotationEnabled: boolean; // Rotar tokens automáticamente
};

// Configuración de sesiones
sessionSettings: {
maxConcurrentSessions: number; // Máximo de sesiones por usuario
maxInactivityMinutes: number; // Tiempo de inactividad antes de logout
extendSessionOnActivity: boolean; // Extender sesión con actividad
requireReauthForSensitive: boolean; // Re-auth para acciones sensibles
};

// Configuración de seguridad
securitySettings: {
enableDeviceFingerprinting: boolean;
enableGeoLocationTracking: boolean;
enableSuspiciousActivityDetection: boolean;
maxFailedLoginAttempts: number;
lockoutDurationMinutes: number;
enableIPWhitelist: boolean;
allowedIPRanges?: string[];
};

isActive: boolean;
environment: 'development' | 'staging' | 'production';
}
Propósito: Preferencias de idioma por usuario Responsabilidades clave:
• Idioma preferido del usuario
• Detección automática vs manual
• Historial de cambios de idioma
• Configuraciones por contexto
interface UserLanguagePreferenceSchema {
preferenceId: ObjectId;
userId: ObjectId;
primaryLanguage: string;
fallbackLanguages: string[];
autoDetectLanguage: boolean;
detectionMethod: 'browser' | 'geolocation' | 'manual';
businessSpecificLanguages: {
businessId: ObjectId;
language: string;
}[];
lastUpdated: Date;
}
Estrategia de Implementación de Traducciones
Servicios de IA para Traducción
Cadena de Fallback (Orden de Prioridad):

1. OpenAI GPT-4 (Mejor calidad, contextual) - Para contenido complejo
2. Google Translate (Rápido, confiable) - Para contenido simple
3. DeepL (Bueno para idiomas europeos) - Respaldo especializado
   Optimización de Costos
   Estrategias de Cache:
   • Cache exacto (mismo texto, mismo par de idiomas)
   • Cache difuso (texto similar con puntuación de similitud alta)
   • Cache de frases (frases comerciales comunes)
   • Cache dinámico (traducciones frecuentemente solicitadas)
   Gestión de Costos:
   • OpenAI GPT-4: ~$0.03 por 1K tokens
   • Google Translate: ~$20 por 1M caracteres
   • Objetivo de 95% de tasa de acierto de cache
   • Traducción bajo demanda (no automática)
   Patrón Base para Todos los Esquemas (Auditoría y Soft Delete)
   Base Schema Pattern
   Todos los esquemas principales heredarán estos campos base:
   interface BaseSchema {
   // Identificación
   \_id: ObjectId;

// Soft Delete
isDeleted: boolean;
deletedAt?: Date;
deletedBy?: ObjectId;
deletionReason?: string;

// Auditoría automática
createdAt: Date;
createdBy: ObjectId;
updatedAt: Date;
updatedBy?: ObjectId;

// Versionado
version: number; // Se incrementa en cada update

// Metadatos de auditoría
lastChangeReason?: string; // Razón del último cambio
changeHistory?: { // Resumen rápido de cambios recientes
totalChanges: number;
lastMajorChange?: Date;
};
}
Middleware de Auditoría (Concepto de Implementación)
// Pre-save middleware para capturar estado anterior
schema.pre('findOneAndUpdate', async function() {
const docToUpdate = await this.model.findOne(this.getFilter());
if (docToUpdate) {
// Capturar estado anterior antes de la actualización
const previousState = docToUpdate.toObject();
this.set('\_\_previousState', previousState);
}
});

// Post-save middleware para crear registro de auditoría
schema.post('findOneAndUpdate', async function(doc) {
const previousState = this.get('\_\_previousState');
if (previousState && doc) {
await createAuditLog({
targetCollection: this.model.collection.name,
targetDocumentId: doc.\_id,
changeType: 'update',
previousValues: previousState,
changedFields: getChangedFields(previousState, doc),
changedBy: this.get('updatedBy'),
version: doc.version
});
}
});
Funciones de Utilidad para Auditoría
/\*\*

- Crea un registro de auditoría para cambios en documentos
  \*/
  async function createAuditLog(params: {
  targetCollection: string;
  targetDocumentId: ObjectId;
  changeType: 'create' | 'update' | 'delete' | 'restore';
  previousValues: Record<string, any>;
  changedFields: string[];
  changedBy: ObjectId;
  version: number;
  changeReason?: string;
  context?: any;
  }) {
  const auditRecord = new AuditLog({
  targetCollection: params.targetCollection,
  targetDocumentId: params.targetDocumentId,
  changeType: params.changeType,
  previousValues: filterSensitiveFields(params.previousValues),
  changedFields: params.changedFields,
  changedBy: params.changedBy,
  changedAt: new Date(),
  version: params.version,
  previousVersion: params.version - 1,
  isDeleteAction: params.changeType === 'delete',
  deletedAt: params.changeType === 'delete' ? new Date() : undefined,
  changeReason: params.changeReason,
  // ... metadatos adicionales
  });

await auditRecord.save();
}

/\*\*

- Reconstruye el estado histórico de un documento
  \*/
  async function reconstructDocumentHistory(
  collection: string,
  documentId: ObjectId,
  atVersion?: number
  ): Promise<any> {
  // Obtener documento actual
  const currentDoc = await getCollection(collection).findById(documentId);
  if (!currentDoc) return null;

// Si no se especifica versión, retornar documento actual
if (!atVersion) return currentDoc;

// Si la versión solicitada es la actual, retornar sin procesar
if (atVersion >= currentDoc.version) return currentDoc;

// Obtener todos los cambios desde la versión solicitada hasta la actual
const auditLogs = await AuditLog.find({
targetCollection: collection,
targetDocumentId: documentId,
version: { $gt: atVersion }
}).sort({ version: -1 }); // Más reciente primero

// Aplicar cambios en reversa (des-hacer cambios)
let reconstructedDoc = { ...currentDoc.toObject() };

for (const log of auditLogs) {
// Aplicar valores anteriores
for (const [field, previousValue] of Object.entries(log.previousValues)) {
reconstructedDoc[field] = previousValue;
}
}

return reconstructedDoc;
}

/\*\*

- Obtiene el historial completo de cambios de un documento
  \*/
  async function getDocumentChangeHistory(
  collection: string,
  documentId: ObjectId
  ): Promise<any[]> {
  const auditLogs = await AuditLog.find({
  targetCollection: collection,
  targetDocumentId: documentId
  }).sort({ version: 1 }).populate('changedBy', 'name email');

return auditLogs.map(log => ({
version: log.version,
changeType: log.changeType,
changedBy: log.changedBy,
changedAt: log.changedAt,
changedFields: log.changedFields,
changeReason: log.changeReason,
// No incluir previousValues por seguridad, solo metadatos
}));
}

/\*\*

- Soft delete con auditoría
  \*/
  async function softDelete(
  collection: string,
  documentId: ObjectId,
  deletedBy: ObjectId,
  reason?: string
  ) {
  const doc = await getCollection(collection).findById(documentId);
  if (!doc || doc.isDeleted) {
  throw new Error('Document not found or already deleted');
  }

// Capturar estado anterior
const previousState = doc.toObject();

// Realizar soft delete
await getCollection(collection).findByIdAndUpdate(documentId, {
isDeleted: true,
deletedAt: new Date(),
deletedBy: deletedBy,
deletionReason: reason,
updatedAt: new Date(),
updatedBy: deletedBy,
$inc: { version: 1 }
});

// Crear registro de auditoría
await createAuditLog({
targetCollection: collection,
targetDocumentId: documentId,
changeType: 'delete',
previousValues: previousState,
changedFields: ['isDeleted', 'deletedAt', 'deletedBy'],
changedBy: deletedBy,
version: doc.version + 1,
changeReason: reason
});
}

/\*\*

- Restaurar documento eliminado
  \*/
  async function restoreDocument(
  collection: string,
  documentId: ObjectId,
  restoredBy: ObjectId,
  reason?: string
  ) {
  const doc = await getCollection(collection).findById(documentId);
  if (!doc || !doc.isDeleted) {
  throw new Error('Document not found or not deleted');
  }

// Capturar estado anterior
const previousState = doc.toObject();

// Restaurar documento
await getCollection(collection).findByIdAndUpdate(documentId, {
isDeleted: false,
$unset: {
deletedAt: 1,
deletedBy: 1,
deletionReason: 1
},
updatedAt: new Date(),
updatedBy: restoredBy,
$inc: { version: 1 }
});

// Crear registro de auditoría
await createAuditLog({
targetCollection: collection,
targetDocumentId: documentId,
changeType: 'restore',
previousValues: previousState,
changedFields: ['isDeleted', 'deletedAt', 'deletedBy'],
changedBy: restoredBy,
version: doc.version + 1,
changeReason: reason
});
}
Relaciones de Esquemas
Business ←→ Address (ubicación) Business ←→ Business Category (clasificación) Business ←→ Business Service (ofertas) Business ←→ News Article (contenido) Business ←→ User Review (retroalimentación) User ←→ User Favorite (preferencias) Business ←→ Geographic Zone (áreas de servicio) User ←→ User Language Preference (configuración de idioma) MultiLanguageContent ←→ Translation Cache (optimización) Todos los Esquemas ←→ Audit Log (seguimiento)

## Prioridades de Implementación

### Fase 1 (MVP - Octubre)

1. **User Schema** (auth básica + preferencias de idioma)
2. **Business Schema** (info principal + multiidioma básico)
3. **Address Schema** (geolocalización)
4. **Role Schema** (RBAC básico)
5. **Business Category Schema** (clasificación + multiidioma)
6. **Translation Cache Schema** (optimización básica)

### Fase 2 (Post-MVP)

7. **Permission Schema** (control de acceso detallado)
8. **News Article Schema** (contenido + multiidioma)
9. **User Review Schema** (retroalimentación + multiidioma)
10. **Media Schema** (multimedia)
11. **Notification Template Schema** (notificaciones + multiidioma)

### Fase 3 (Características Avanzadas)

12. **Business Service Schema** (servicios detallados)
13. **Geographic Zone Schema** (gestión geográfica avanzada)
14. **Location Restriction Schema** (restricciones geográficas)
15. Todos los esquemas restantes

## Consideraciones Técnicas

### Estrategia de Indexación (Actualizado con Seguridad)

- **Índices geográficos**: Para consultas basadas en ubicación (2dsphere)
- **Índices de texto**: Para búsqueda de contenido multiidioma
- **Índices compuestos**: Para filtros complejos (categoría + ubicación + idioma)
- **Índices TTL**: Para cache de traducciones y sesiones expiradas
- **Índices de seguridad**: Para autenticación y auditoría rápida

```typescript
// Índices de seguridad críticos
UserSessionSchema.index({ sessionToken: 1 }, { unique: true });
UserSessionSchema.index({ userId: 1, isActive: 1 });
UserSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL automático
UserSessionSchema.index({
  userId: 1,
  createdAt: -1
}, { name: 'user_sessions_by_date' });

// Índices para detección de seguridad
UserSessionSchema.index({
  ipAddress: 1,
  userId: 1,
  createdAt: -1
}, { name: 'security_monitoring_index' });

UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ 'oauthProviders.google.providerId': 1 }, { sparse: true });
UserSchema.index({ 'oauthProviders.facebook.providerId': 1 }, { sparse: true });
Validación de Datos y Seguridad
•	Esquemas JSON: Validación en MongoDB con reglas de seguridad
•	Validación de sesiones: Verificación de integridad de tokens
•	Sanitización: Prevención de XSS en contenido traducido y user input
•	Límites de longitud: Por idioma y tipo de contenido
•	Validación de IP: Para restricciones geográficas y detección de anomalías
•	Rate limiting: A nivel de esquema y middleware
Rendimiento y Escalabilidad con Seguridad
•	Particionamiento: Por región geográfica y por usuario
•	Replicación: Para disponibilidad global con réplicas de solo lectura
•	Agregaciones optimizadas: Para métricas de traducción y auditoría
•	CDN: Para contenido traducido estático
•	Cache de sesiones: Redis para sesiones activas (fallback a MongoDB)
•	Separación de datos: Datos sensibles en colecciones separadas
Ejemplos Prácticos de Uso
Ejemplo 1: Actualización de Usuario
// Estado inicial
const user = {
  _id: ObjectId("64a1b2c3d4e5f6789abcdef0"),
  code: 1,
  name: "user1",
  email: "email@gmail.com",
  version: 1
};

// Actualización
await User.findByIdAndUpdate(user._id, {
  code: 2,
  email: "email1@gmail.com",
  updatedBy: ObjectId("admin123"),
  $inc: { version: 1 }
});

// Auditoría automática creada:
{
  targetCollection: "users",
  targetDocumentId: ObjectId("64a1b2c3d4e5f6789abcdef0"),
  changeType: "update",
  previousValues: {
    code: 1,
    email: "email@gmail.com"
  },
  changedFields: ["code", "email"],
  changedBy: ObjectId("admin123"),
  version: 2,
  previousVersion: 1
}
Ejemplo 2: Reconstrucción Histórica
// Obtener cómo era el usuario en la versión 1
const userAtVersion1 = await reconstructDocumentHistory(
  'users',
  ObjectId("64a1b2c3d4e5f6789abcdef0"),
  1
);

// Resultado:
{
  _id: ObjectId("64a1b2c3d4e5f6789abcdef0"),
  code: 1,                    // Valor original
  name: "user1",
  email: "email@gmail.com",   // Valor original
  version: 1
}
Ejemplo 3: Soft Delete
// Eliminar usuario
await softDelete(
  'users',
  ObjectId("64a1b2c3d4e5f6789abcdef0"),
  ObjectId("admin123"),
  "Usuario inactivo por 6 meses"
);

// Estado resultante:
{
  _id: ObjectId("64a1b2c3d4e5f6789abcdef0"),
  code: 2,
  name: "user1",
  email: "email1@gmail.com",
  isDeleted: true,
  deletedAt: Date("2024-07-31T10:00:00Z"),
  deletedBy: ObjectId("admin123"),
  deletionReason: "Usuario inactivo por 6 meses",
  version: 3
}
Relaciones de Esquemas
Consideraciones de Rendimiento y Almacenamiento
Gestión del Crecimiento de Auditoría:
•	Particionamiento temporal: Dividir auditorías por mes/año
•	Archivado automático: Mover auditorías antiguas a almacenamiento frío
•	Límites de retención: Configurar políticas de retención (ej: 7 años)
•	Compresión: Comprimir previousValues para ahorrar espacio
Optimizaciones:
// TTL para auditorías (opcional, según requisitos legales)
AuditLogSchema.index(
  { changedAt: 1 },
  {
    expireAfterSeconds: 60 * 60 * 24 * 365 * 7, // 7 años
    name: 'audit_ttl_index'
  }
);

// Filtrado de campos sensibles
function filterSensitiveFields(obj: any): any {
  const sensitiveFields = ['passwordHash', 'tokens', 'privateKeys'];
  const filtered = { ...obj };

  sensitiveFields.forEach(field => {
    if (filtered[field]) {
      filtered[field] = '[FILTERED]';
    }
  });

  return filtered;
}
Beneficios del Sistema de Auditoría por Capas:
1.	Versionado Completo: Reconstruir cualquier estado histórico
2.	Eficiencia de Almacenamiento: Solo guardar cambios, no duplicar documentos completos
3.	Trazabilidad Total: Saber exactamente quién cambió qué y cuándo
4.	Recuperación de Datos: Posibilidad de deshacer cambios específicos
5.	Cumplimiento Legal: Auditoría completa para regulaciones
6.	Debugging: Rastrear problemas hasta el cambio específico que los causó
Casos de Uso Avanzados:
•	Comparar estados entre versiones específicas
•	Generar reportes de actividad por usuario/periodo
•	Detectar patrones de cambios sospechosos
•	Restaurar documentos a estados específicos
•	Análisis de impacto de cambios masivos
Documentación y Estándares
Convenciones de Nombres (Inglés):
•	camelCase para campos
•	PascalCase para esquemas
•	Prefijos descriptivos (is, has, can para booleanos)
•	Sufijos estándar (Id, At, Count)
Documentación TypeDoc/Swagger:
•	JSDoc para todos los campos
•	Ejemplos de uso en comentarios
•	Validaciones documentadas
•	Relaciones explícitas entre esquemas
Ejemplo de Documentación:
/**
 * Business entity with multi-language support
 * @swagger
 * @example
 * {
 *   "businessName": {
 *     "original": { "language": "es", "text": "Restaurante El Buen Sabor" },
 *     "translations": {
 *       "en": { "text": "The Good Flavor Restaurant", "translatedAt": "2024-07-31T10:00:00Z" }
 *     }
 *   }
 * }
 */
interface BusinessSchema {
  /** Unique business identifier */
  businessId: ObjectId;

  /** Multi-language business name */
  businessName: MultiLanguageContent;

  /** Detailed business description with translation support */
  description: MultiLanguageContent;
  // ... más campos
}
Beneficios de la Arquitectura
Para Propietarios de Empresas
•	Escriben en su idioma nativo
•	Expansión automática a mercados internacionales
•	Sin trabajo manual de traducción
•	Mayor alcance de clientes
Para Usuarios
•	Experiencia en idioma nativo
•	Mejor comprensión de servicios
•	Mayor confianza y engagement
•	Búsquedas más efectivas
Para la Plataforma
•	Ventaja competitiva única
•	Mayor retención de usuarios
•	Justifica precios premium
•	Escalabilidad internacional automática

```

Diagrama de Clases

```
classDiagram
    %% ==================== CLASES BASE ====================
    class BaseSchema {
        <<Abstract>>
        #isDeleted: Boolean
        #deletedAt: Date
        #deletedBy: ObjectId
        #deletionReason: String
        #createdAt: Date
        #createdBy: ObjectId
        #updatedAt: Date
        #updatedBy: ObjectId
        #version: Number
        #lastChangeReason: String
        +softDelete(deletedBy, reason)
        +restore(restoredBy, reason)
        +getAuditInfo()
    }

    class MultiLanguageContent {
        -original: OriginalContent
        -translations: Map~String, Translation~
        -translationConfig: Object
        -lastUpdated: Date
        +getText(language, fallbackLanguages)
        +addTranslation(language, text, options)
        +hasTranslation(language)
        +needsTranslationUpdate(language)
    }

    %% ==================== MODELOS PRINCIPALES ====================
    class User {
        -email: String
        -passwordHash: String
        -profile: UserProfile
        -oauthProviders: Object
        -roles: ObjectId[]
        -isEmailVerified: Boolean
        -preferences: Object
        +validatePassword(password)
        +setPassword(password)
        +connectOAuthProvider(provider, providerData)
        +updatePreferences(newPreferences)
        +generateEmailVerificationToken()
        +generatePasswordResetToken()
    }

    class Role {
        -roleName: String
        -displayName: MultiLanguageContent
        -description: MultiLanguageContent
        -permissions: Permission[]
        -hierarchy: Number
        -roleType: String
        +hasPermission(resource, action, scope)
        +addPermission(resource, actions, scope, conditions)
        +removePermission(resource, action)
        +canManageCompany(companyId)
    }

    class Business {
        -businessName: MultiLanguageContent
        -description: MultiLanguageContent
        -ownerId: ObjectId
        -categories: ObjectId[]
        -primaryCategory: ObjectId
        -address: ObjectId
        -coordinates: GeoJSON
        -contactInfo: ContactInfo
        -operatingHours: BusinessHours[]
        +isOpenNow()
        +isOpenAt(date)
        +addManager(userId, role, permissions, addedBy)
        +canUserManage(userId)
        +generateUniqueSlug(baseName)
    }

    class BusinessCategory {
        -categoryName: MultiLanguageContent
        -description: MultiLanguageContent
        -parentCategory: ObjectId
        -categorySlug: String
        -categoryLevel: Number
        -industryCodes: Object
        +getHierarchy()
        +getSubcategories(options)
        +updateStats()
        +calculatePopularityScore(businessCount, avgRating, totalViews)
    }

    class Address {
        -streetAddress: String
        -city: String
        -state: String
        -country: String
        -postalCode: String
        -location: Coordinates
        -formattedAddress: FormattedAddress
        -businessId: ObjectId
        -userId: ObjectId
        +autoFormatAddress()
        +distanceTo(otherAddress)
        +validateWithService(service)
        +isWithinRadius(centerCoordinates, radiusInMeters)
    }

    class UserSession {
        -userId: ObjectId
        -sessionToken: String
        -deviceFingerprint: String
        -ipAddress: String
        -deviceInfo: DeviceInfo
        -location: LocationInfo
        -isActive: Boolean
        +isExpired()
        +markAsCompromised(reason)
        +logSuspiciousActivity(type, description, severity, additionalData)
        +logFingerprintChange(newFingerprint, changedComponents)
        +extendSession(additionalHours)
    }

    %% ==================== ESQUEMAS EMBEBIDOS ====================
    class UserProfile {
        -firstName: String
        -lastName: String
        -avatar: String
        -dateOfBirth: Date
        -phone: String
        -bio: String
        -isActive: Boolean
    }

    class Permission {
        -resource: String
        -actions: String[]
        -scope: String
        -conditions: Object
        -geographicRestrictions: Object
        -timeRestrictions: Object
    }

    class ContactInfo {
        -primaryPhone: String
        -secondaryPhone: String
        -whatsapp: String
        -email: String
        -website: String
        -socialMedia: Object
    }

    class BusinessHours {
        -dayOfWeek: Number
        -openTime: String
        -closeTime: String
        -isClosed: Boolean
        -is24Hours: Boolean
    }

    class Coordinates {
        -type: String
        -coordinates: Number[]
        -accuracy: Number
        -source: String
        -verifiedAt: Date
    }

    class DeviceInfo {
        -browser: String
        -os: String
        -device: String
        -deviceType: String
        -timezone: String
        -language: String
        -hardwareConcurrency: Number
    }

    class LocationInfo {
        -country: String
        -city: String
        -region: String
        -coordinates: Number[]
        -isVpnDetected: Boolean
        -isp: String
        -isEuCountry: Boolean
    }

    %% ==================== RELACIONES ====================
    User "1" -- "*" UserSession : tiene
    User "1" -- "*" Role : tiene
    User "1" -- "*" Business : es_propietario_de
    User "1" -- "0..1" Address : tiene

    Business "1" -- "*" BusinessCategory : tiene_categorías
    Business "1" -- "1" Address : tiene_ubicación

    BusinessCategory "1" -- "0..1" BusinessCategory : tiene_padre
    BusinessCategory "1" -- "*" BusinessCategory : tiene_hijos

    Role "1" -- "0..1" Role : tiene_padre

    BaseSchema <|-- User
    BaseSchema <|-- Role
    BaseSchema <|-- Business
    BaseSchema <|-- BusinessCategory
    BaseSchema <|-- Address
    BaseSchema <|-- UserSession

    User *-- UserProfile : contiene
    Role *-- Permission : contiene
    Business *-- ContactInfo : contiene
    Business *-- BusinessHours : contiene
    Address *-- Coordinates : contiene
    UserSession *-- DeviceInfo : contiene
    UserSession *-- LocationInfo : contiene

    MultiLanguageContent <|.. Business : utiliza
    MultiLanguageContent <|.. BusinessCategory : utiliza
    MultiLanguageContent <|.. Role : utiliza

´´´
```
