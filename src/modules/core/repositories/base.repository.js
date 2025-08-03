import { Types } from "mongoose";
import { AuditRepository } from "./audit.repository.js";

export class GenericRepository {
  constructor(model) {
    this.model = model;
    this.modelName = model.modelName;
  }

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

      return await document.save(options); // <- aquí se aplica la sesión si viene
    } catch (error) {
      console.log(error);
      throw new Error(`Error creando ${this.modelName}: ${error.message}`);
    }
  }

  async createMany(data, options = {}) {
    return await this.model.insertMany(data, options);
  }

  async deleteMany(query, options = {}) {
    return await this.model.deleteMany(query, options);
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

    // Clonar el query base (para no mutarlo)
    const baseQuery = { ...query };

    // Construir filtro para eliminados - CORRECCIÓN AQUÍ
    const deletedFilter = includeDeleted
      ? {}
      : { $or: [{ deletedAt: null }, { deletedAt: { $exists: false } }] };
    // Combinar correctamente usando $and si es necesario
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
   * Obtener documento por ID
   * @param {string} id - ID del documento
   * @param {object} options - Opciones adicionales
   * @param {string|array|object} options.populate - Campos a popular
   * @param {boolean} options.includeDeleted - Incluir documentos eliminados
   * @param {boolean} options.lean - Usar lean() (true por defecto)
   */
  async findById(id, options = {}) {
    try {
      // Validar que el ID sea un ObjectId válido
      if (!Types.ObjectId.isValid(id)) {
        throw new Error("ID no válido");
      }

      const {
        populate = "",
        includeDeleted = false,
        lean = true, // Lean activado por defecto
      } = options;

      const query = this.model.findById(id);

      // Solo aplicar filtro de eliminación si no se incluyen los eliminados
      if (!includeDeleted) {
        query.where({
          $or: [{ deletedAt: null }, { deletedAt: { $exists: false } }],
        });
      }

      // Aplicar populate si se especificó
      if (Array.isArray(populate)) {
        for (const p of populate) {
          query.populate(p);
        }
      } else if (typeof populate === "string" || typeof populate === "object") {
        query.populate(populate);
      }

      // Aplicar lean sólo si se especifica (o por defecto true)
      if (lean) {
        query.lean();
      }

      const document = await query;

      if (!document) {
        throw new Error("Documento no encontrado");
      }

      // Si se usó lean pero necesitamos los métodos, convertimos a instancia
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
   * Actualizar documento con auditoría
   */
  async update(id, updateData, userData, options = {}) {
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("ID no válido");
    }

    try {
      // Obtener documento original
      const originalDoc = await this.model.findById(id).lean();
      if (!originalDoc || originalDoc.deletedAt) {
        throw new Error("Documento no encontrado");
      }

      // Preparar datos de actualización
      const dataToUpdate = {
        ...updateData,
        updatedBy: userData.userId,
        updatedAt: new Date(),
      };

      // Usar session para transacciones si es necesario
      const session = options.session;
      const updateOptions = {
        new: true,
        lean: true,
        session,
        ...options,
      };

      // Actualizar documento
      const updatedDoc = await this.model.findByIdAndUpdate(
        id,
        dataToUpdate,
        updateOptions
      );

      // Guardar auditoría de cambios
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
        // No fallar la actualización por error de auditoría
      }

      return updatedDoc;
    } catch (error) {
      console.error(`Error al actualizar ${this.modelName}:`, error);
      throw error;
    }
  }
  /**
   * Eliminación suave (soft delete)
   */
  async softDelete(id, userData) {
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("ID no válido");
    }

    const document = await this.model.findById(id);
    if (!document || document.deletedAt) {
      throw new Error("Documento no encontrado");
    }

    // Marcar como eliminado
    document.deletedBy = userData.userId;
    document.deletedAt = new Date();

    return await document.save();
  }

  /**
   * Eliminación forzada con auditoría
   */
  async forceDelete(id, userData) {
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("ID no válido");
    }

    // Obtener documento antes de eliminar
    const documentToDelete = await this.model.findById(id).lean();
    if (!documentToDelete) {
      throw new Error("Documento no encontrado");
    }

    // Guardar respaldo en auditoría
    await AuditRepository.saveDeleteBackup({
      schema: this.modelName,
      documentId: id,
      documentToDelete,
      userData,
    });

    // Eliminar documento
    await this.model.findByIdAndDelete(id);

    return { message: "Documento eliminado permanentemente" };
  }

  /**
   * Restaurar documento eliminado (soft delete)
   */
  async restore(id, userData) {
    if (!Types.ObjectId.isValid(id)) {
      throw new Error("ID no válido");
    }

    const document = await this.model.findById(id);
    if (!document) {
      throw new Error("Documento no encontrado");
    }
    if (!document.deletedAt) {
      throw new Error("Documento no está eliminado");
    }

    // Restaurar documento
    document.deletedBy = undefined;
    document.deletedAt = undefined;
    document.updatedBy = userData.userId;
    document.updatedAt = new Date();

    return await document.save();
  }
  /**
   * Obtener historial de auditoría de un documento
   */
  async getAuditHistory(id, options = {}) {
    return await AuditRepository.getDocumentHistory(
      id,
      this.modelName,
      options
    );
  }

  /**
   * Búsqueda con filtros avanzados
   */
  async search(searchParams, options = {}) {
    const { text, dateFrom, dateTo, createdBy, ...otherFilters } = searchParams;

    let query = { ...otherFilters };

    // Excluir eliminados
    /*if (!options.includeDeleted) {
      query.deletedAt = { $exists: false };
    }*/

    // Búsqueda por texto (requiere índice de texto en el modelo)
    if (text) {
      query.$text = { $search: text };
    }

    // Filtro por rango de fechas
    if (dateFrom || dateTo) {
      query.createdAt = {};
      if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
      if (dateTo) query.createdAt.$lte = new Date(dateTo);
    }

    // Filtro por creador
    if (createdBy) {
      query.createdBy = new Types.ObjectId(createdBy);
    }

    return await this.findAll(query, options);
  }

  /**
   * Actualización en lote con auditoría
   */
  async updateMany(filter, updateData, userData) {
    // Obtener documentos que serán actualizados
    const docsToUpdate = await this.model.find(filter).lean();

    if (docsToUpdate.length === 0) {
      return { modifiedCount: 0 };
    }

    // Actualizar documentos
    const result = await this.model.updateMany(filter, {
      ...updateData,
      updatedBy: userData.userId,
      updatedAt: new Date(),
    });

    // Auditar cada documento actualizado
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
}
