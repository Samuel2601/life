// =============================================================================
// src/modules/core/repositories/base.repository.js - VERSIÓN REORGANIZADA
// Métodos organizados por categorías y estándar camelCase
// =============================================================================
import { Types } from "mongoose";
import { AuditRepository } from "../../../security/audit/repositories/audit.repository.js";

export class BaseRepository {
  constructor(model) {
    this.model = model;
    this.modelName = model.modelName;
    this.defaultLookups = new Map();
    this.initializeDefaultConfig();
  }

  /**
   * Inicializar configuración por defecto
   */
  initializeDefaultConfig() {
    const schemaObj = this.model.schema.obj;
    this.autoDetectLookups(schemaObj);
  }

  /**
   * Auto-detectar relaciones para lookups automáticos
   */
  autoDetectLookups(schemaObj, prefix = "") {
    for (const [field, definition] of Object.entries(schemaObj)) {
      if (definition.ref) {
        this.defaultLookups.set(prefix + field, {
          from: this.getCollectionName(definition.ref),
          localField: prefix + field,
          foreignField: "_id",
          as: prefix + field,
          model: definition.ref,
        });
      } else if (Array.isArray(definition) && definition[0]?.ref) {
        this.defaultLookups.set(prefix + field, {
          from: this.getCollectionName(definition[0].ref),
          localField: prefix + field,
          foreignField: "_id",
          as: prefix + field,
          model: definition[0].ref,
        });
      } else if (definition.type && typeof definition.type === "object") {
        this.autoDetectLookups(definition.type, prefix + field + ".");
      }
    }
  }

  /**
   * Obtener nombre de colección desde nombre de modelo
   */
  getCollectionName(modelName) {
    const collectionNames = {
      User: "users",
      Role: "roles",
      Business: "businesses",
      UserSession: "usersessions",
      Address: "addresses",
      Review: "reviews",
      Category: "categories",
    };
    return collectionNames[modelName] || modelName.toLowerCase() + "s";
  }

  // =============================================================================
  // 📝 MÉTODOS CRUD BÁSICOS
  // =============================================================================

  /**
   * Crear nuevo documento
   */
  async create(data, userData, options = {}) {
    try {
      const document = new this.model({
        ...data,
        createdBy: userData.userId,
        updatedBy: userData.userId,
      });

      return await document.save(options);
    } catch (error) {
      console.error(`Error creando ${this.modelName}:`, error);
      throw new Error(`Error creando ${this.modelName}: ${error.message}`);
    }
  }

  /**
   * Obtener documento por ID
   */
  async findById(id, options = {}) {
    try {
      if (!Types.ObjectId.isValid(id)) {
        throw new Error("ID no válido");
      }

      const { populate = "", includeDeleted = false, lean = true } = options;

      const query = this.model.findById(id);

      if (!includeDeleted) {
        query.where({
          $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
        });
      }

      if (Array.isArray(populate)) {
        for (const p of populate) {
          query.populate(p);
        }
      } else if (typeof populate === "string" || typeof populate === "object") {
        query.populate(populate);
      }

      if (lean) {
        query.lean();
      }

      const document = await query;

      if (!document) {
        throw new Error("Documento no encontrado");
      }

      if (lean && options.returnInstance) {
        return this.model.hydrate(document);
      }

      return document;
    } catch (error) {
      console.error("Error en findById:", error);
      throw new Error(`Error obteniendo documento: ${error.message}`);
    }
  }

  /**
   * Obtener documentos con paginación
   */
  async findAll(query = {}, options = {}) {
    const {
      page = 1,
      limit = 10,
      sort = "-createdAt",
      populate = "",
      select = "",
      includeDeleted = false,
    } = options;

    const baseQuery = { ...query };
    const deletedFilter = includeDeleted
      ? {}
      : { $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }] };

    const finalQuery =
      Object.keys(baseQuery).length > 0
        ? { $and: [baseQuery, deletedFilter] }
        : deletedFilter;

    return await this.model.paginate(finalQuery, {
      page,
      limit,
      sort,
      populate,
      select,
      lean: true,
    });
  }

  /**
   * Actualizar documento con auditoría
   */
  async update(id, updateData, userData, options = {}) {
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("ID no válido");
    }

    try {
      const originalDoc = await this.model.findById(id).lean();
      if (!originalDoc || originalDoc.isDeleted) {
        throw new Error("Documento no encontrado");
      }

      const dataToUpdate = {
        ...updateData,
        updatedBy: userData.userId,
        updatedAt: new Date(),
      };

      const session = options.session;
      const updateOptions = {
        new: true,
        lean: true,
        session,
        ...options,
      };

      const updatedDoc = await this.model.findByIdAndUpdate(
        id,
        dataToUpdate,
        updateOptions
      );

      // Auditoría
      try {
        await AuditRepository.saveUpdateWithDetection(
          {
            schema: this.modelName,
            documentId: id,
            originalDoc,
            updatedDoc,
            userData,
          },
          options
        );
      } catch (auditError) {
        console.error("Error en auditoría:", auditError);
      }

      return updatedDoc;
    } catch (error) {
      console.error(`Error al actualizar ${this.modelName}:`, error);
      throw error;
    }
  }

  /**
   * Búsqueda básica con filtros
   */
  async search(searchParams, options = {}) {
    const { text, dateFrom, dateTo, createdBy, ...otherFilters } = searchParams;

    let query = { ...otherFilters };

    if (text) {
      const textFields = this.getTextSearchFields();
      if (textFields.length > 0) {
        query.$or = textFields.map((field) => ({
          [field]: { $regex: text, $options: "i" },
        }));
      }
    }

    if (dateFrom || dateTo) {
      query.createdAt = {};
      if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
      if (dateTo) query.createdAt.$lte = new Date(dateTo);
    }

    if (createdBy) {
      query.createdBy = new Types.ObjectId(createdBy);
    }

    return await this.findAll(query, options);
  }

  // =============================================================================
  // 🗑️ MÉTODOS DE SOFT DELETE / RESTORE
  // =============================================================================

  /**
   * Soft delete de un documento
   */
  async softDelete(id, userData, reason = null) {
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("ID no válido");
    }

    const document = await this.model.findById(id);
    if (!document || document.isDeleted) {
      throw new Error("Documento no encontrado o ya eliminado");
    }

    document.isDeleted = true;
    document.deletedBy = userData.userId;
    document.deletedAt = new Date();
    document.deletionReason = reason;
    document.updatedBy = userData.userId;

    return await document.save();
  }

  /**
   * Restaurar documento eliminado
   */
  async restore(id, userData, reason = null) {
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("ID no válido");
    }

    const document = await this.model.findById(id);
    if (!document) {
      throw new Error("Documento no encontrado");
    }
    if (!document.isDeleted) {
      throw new Error("Documento no está eliminado");
    }

    document.isDeleted = false;
    document.deletedBy = undefined;
    document.deletedAt = undefined;
    document.deletionReason = undefined;
    document.updatedBy = userData.userId;
    document.updatedAt = new Date();
    document.lastChangeReason = reason || "Documento restaurado";

    return await document.save();
  }

  /**
   * Eliminación permanente (force delete)
   */
  async forceDelete(id, userData) {
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("ID no válido");
    }

    const documentToDelete = await this.model.findById(id).lean();
    if (!documentToDelete) {
      throw new Error("Documento no encontrado");
    }

    // Backup para auditoría
    try {
      await AuditRepository.saveDeleteBackup({
        schema: this.modelName,
        documentId: id,
        documentToDelete,
        userData,
      });
    } catch (auditError) {
      console.error("Error en auditoría de eliminación:", auditError);
    }

    await this.model.findByIdAndDelete(id);

    return { message: "Documento eliminado permanentemente" };
  }

  // =============================================================================
  // 📦 MÉTODOS BULK (MASIVOS)
  // =============================================================================

  /**
   * Crear múltiples documentos
   */
  async createMany(data, userData, options = {}) {
    const documentsToInsert = data.map((item) => ({
      ...item,
      createdBy: userData.userId,
      updatedBy: userData.userId,
    }));

    return await this.model.insertMany(documentsToInsert, options);
  }

  /**
   * Actualizar múltiples documentos
   */
  async updateMany(filter, updateData, userData, options = {}) {
    // Obtener documentos originales para auditoría
    const docsToUpdate = await this.model.find(filter).lean();

    if (docsToUpdate.length === 0) {
      return { modifiedCount: 0 };
    }

    const result = await this.model.updateMany(filter, {
      ...updateData,
      updatedBy: userData.userId,
      updatedAt: new Date(),
      $inc: { version: 1 },
    });

    // Auditoría para cada documento actualizado
    for (const originalDoc of docsToUpdate) {
      try {
        const updatedDoc = await this.model.findById(originalDoc._id).lean();

        await AuditRepository.saveUpdateWithDetection({
          schema: this.modelName,
          documentId: originalDoc._id,
          originalDoc,
          updatedDoc,
          userData: {
            ...userData,
            batchOperation: true,
          },
        });
      } catch (auditError) {
        console.error(
          `Error auditando documento ${originalDoc._id}:`,
          auditError
        );
      }
    }

    return result;
  }

  /**
   * Eliminar múltiples documentos (soft delete)
   */
  async softDeleteMany(filter, userData, reason = null) {
    return await this.model.updateMany(filter, {
      $set: {
        isDeleted: true,
        deletedAt: new Date(),
        deletedBy: userData.userId,
        deletionReason: reason,
        updatedBy: userData.userId,
        updatedAt: new Date(),
      },
      $inc: { version: 1 },
    });
  }

  /**
   * Restaurar múltiples documentos
   */
  async restoreMany(filter, userData, reason = null) {
    return await this.model.updateMany(filter, {
      $set: {
        isDeleted: false,
        deletedAt: null,
        deletedBy: null,
        deletionReason: null,
        updatedBy: userData.userId,
        updatedAt: new Date(),
        lastChangeReason: reason || "Documentos restaurados",
      },
      $inc: { version: 1 },
    });
  }

  /**
   * Eliminación permanente múltiple
   */
  async forceDeleteMany(filter, userData) {
    const documentsToDelete = await this.model.find(filter).lean();

    // Backup para auditoría
    for (const doc of documentsToDelete) {
      try {
        await AuditRepository.saveDeleteBackup({
          schema: this.modelName,
          documentId: doc._id,
          documentToDelete: doc,
          userData: { ...userData, batchOperation: true },
        });
      } catch (auditError) {
        console.error(`Error auditando eliminación ${doc._id}:`, auditError);
      }
    }

    const result = await this.model.deleteMany(filter);

    return {
      deletedCount: result.deletedCount,
      message: `${result.deletedCount} documentos eliminados permanentemente`,
    };
  }

  // =============================================================================
  // 🔄 FUNCIÓN UNIFICADA PARA AGGREGATION PIPELINE
  // =============================================================================

  /**
   * Función unificada para ejecutar pipelines de agregación
   * Reemplaza searchWithAggregation, findWithJoins y aggregate
   */
  async executeAggregationPipeline(config = {}) {
    try {
      const {
        // Configuración básica
        pipeline = [],
        filters = {},
        options = {},

        // Lookups y joins
        autoLookups = false,
        customLookups = [],

        // Búsqueda
        searchText = "",
        searchFields = [],

        // Configuración avanzada
        facets = null,
        groupBy = null,
        statsConfig = null,
      } = config;

      console.log(
        `🔍 Ejecutando pipeline de agregación para ${this.modelName}`
      );

      const {
        page = 1,
        limit = 10,
        sort = { createdAt: -1 },
        includeDeleted = false,
        enablePagination = true,
      } = options;

      const aggregationPipeline = [];

      // 1. Filtro inicial para soft delete
      if (!includeDeleted) {
        aggregationPipeline.push({
          $match: {
            $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
          },
        });
      }

      // 2. Lookups automáticos si están habilitados
      if (autoLookups) {
        for (const [field, lookupConfig] of this.defaultLookups) {
          aggregationPipeline.push({
            $lookup: {
              from: lookupConfig.from,
              localField: lookupConfig.localField,
              foreignField: lookupConfig.foreignField,
              as: lookupConfig.as,
              pipeline: this.getDefaultProjectionPipeline(lookupConfig.model),
            },
          });

          // Unwind si no es array
          if (!Array.isArray(this.model.schema.obj[field])) {
            aggregationPipeline.push({
              $unwind: {
                path: `$${lookupConfig.as}`,
                preserveNullAndEmptyArrays: true,
              },
            });
          }
        }
      }

      // 3. Lookups personalizados
      for (const lookup of customLookups) {
        aggregationPipeline.push({ $lookup: lookup });

        if (lookup.unwind) {
          aggregationPipeline.push({
            $unwind: {
              path: `$${lookup.as}`,
              preserveNullAndEmptyArrays: lookup.preserveNull !== false,
            },
          });
        }
      }

      // 4. Pipeline personalizado (stages adicionales)
      aggregationPipeline.push(...pipeline);

      // 5. Match de filtros de búsqueda
      const searchMatch = this.buildSearchMatch({
        ...filters,
        searchText,
        searchFields,
      });
      if (Object.keys(searchMatch).length > 0) {
        aggregationPipeline.push({ $match: searchMatch });
      }

      // 6. Agrupación si se especifica
      if (groupBy) {
        const groupStage = this.buildGroupStage(groupBy, statsConfig);
        aggregationPipeline.push(groupStage);
      }

      // 7. Facets personalizados o paginación
      if (facets) {
        aggregationPipeline.push({ $facet: facets });
      } else if (enablePagination) {
        const skip = (page - 1) * limit;

        aggregationPipeline.push({
          $facet: {
            data: [{ $sort: sort }, { $skip: skip }, { $limit: limit }],
            totalCount: [{ $count: "count" }],
          },
        });
      }

      console.log(
        "🔗 Pipeline final:",
        JSON.stringify(aggregationPipeline, null, 2)
      );

      const result = await this.model.aggregate(aggregationPipeline);

      // Procesar resultado según el tipo de pipeline
      if (facets) {
        return result[0] || {};
      } else if (enablePagination) {
        const docs = result[0]?.data || [];
        const totalDocs = result[0]?.totalCount[0]?.count || 0;
        const totalPages = Math.ceil(totalDocs / limit);

        return {
          docs,
          totalDocs,
          totalPages,
          page,
          limit,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1,
          nextPage: page < totalPages ? page + 1 : null,
          prevPage: page > 1 ? page - 1 : null,
          pagingCounter: (page - 1) * limit + 1,
        };
      }

      return result;
    } catch (error) {
      console.error("❌ Error en pipeline de agregación:", error);
      throw new Error(`Error en agregación: ${error.message}`);
    }
  }

  // =============================================================================
  // 🛠️ MÉTODOS AUXILIARES
  // =============================================================================

  /**
   * Construir match de búsqueda desde filtros
   */
  buildSearchMatch(filters) {
    const match = {};
    const {
      searchText,
      searchFields = [],
      dateFrom,
      dateTo,
      createdBy,
      updatedBy,
      ...otherFilters
    } = filters;

    // Búsqueda de texto
    if (searchText) {
      const fieldsToSearch =
        searchFields.length > 0 ? searchFields : this.getTextSearchFields();

      if (fieldsToSearch.length > 0) {
        match.$or = fieldsToSearch.map((field) => ({
          [field]: { $regex: searchText, $options: "i" },
        }));
      }
    }

    // Filtro por rango de fechas
    if (dateFrom || dateTo) {
      match.createdAt = {};
      if (dateFrom) match.createdAt.$gte = new Date(dateFrom);
      if (dateTo) match.createdAt.$lte = new Date(dateTo);
    }

    // Filtros de auditoría
    if (createdBy) match.createdBy = new Types.ObjectId(createdBy);
    if (updatedBy) match.updatedBy = new Types.ObjectId(updatedBy);

    // Otros filtros específicos
    Object.assign(match, otherFilters);

    return match;
  }

  /**
   * Construir stage de agrupación
   */
  buildGroupStage(groupBy, statsConfig = {}) {
    const {
      countField = "count",
      dateField = "createdAt",
      sumFields = [],
      avgFields = [],
    } = statsConfig;

    const groupStage = {
      _id: groupBy,
      [countField]: { $sum: 1 },
    };

    if (dateField) {
      groupStage.firstDate = { $min: `$${dateField}` };
      groupStage.lastDate = { $max: `$${dateField}` };
    }

    // Campos de suma
    for (const field of sumFields) {
      groupStage[`total_${field}`] = { $sum: `$${field}` };
    }

    // Campos de promedio
    for (const field of avgFields) {
      groupStage[`avg_${field}`] = { $avg: `$${field}` };
    }

    return { $group: groupStage };
  }

  /**
   * Obtener campos para búsqueda de texto
   */
  getTextSearchFields() {
    const fields = [];
    const schemaObj = this.model.schema.obj;

    for (const [field, definition] of Object.entries(schemaObj)) {
      if (
        definition.type === String &&
        !field.includes("password") &&
        !field.includes("token") &&
        !field.includes("hash")
      ) {
        fields.push(field);
      }
    }

    return fields;
  }

  /**
   * Obtener pipeline de proyección por defecto para un modelo
   */
  getDefaultProjectionPipeline(modelName) {
    const commonExclusions = {
      __v: 0,
      isDeleted: 0,
      deletedAt: 0,
      deletedBy: 0,
      deletionReason: 0,
    };

    const modelSpecificExclusions = {
      User: {
        passwordHash: 0,
        emailVerificationToken: 0,
        passwordResetToken: 0,
      },
      UserSession: {
        accessTokenHash: 0,
        refreshTokenHash: 0,
        sessionToken: 0,
      },
    };

    const exclusions = {
      ...commonExclusions,
      ...(modelSpecificExclusions[modelName] || {}),
    };

    return [{ $project: exclusions }];
  }

  /**
   * Obtener historial de auditoría
   */
  async getAuditHistory(id, options = {}) {
    return await AuditRepository.getDocumentHistory(
      id,
      this.modelName,
      options
    );
  }
}
