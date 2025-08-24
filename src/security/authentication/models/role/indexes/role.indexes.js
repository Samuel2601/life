export function applyRoleIndexes(schema) {
  // Índices únicos
  schema.index({ roleName: 1 }, { unique: true });

  // Índices compuestos para consultas frecuentes
  schema.index({ hierarchy: 1, isActive: 1 });
  schema.index({ isActive: 1, isSystemRole: 1 });
  schema.index({
    "metadata.category": 1,
    isActive: 1,
    "metadata.sortOrder": 1,
  });
  schema.index({ parentRole: 1, hierarchy: 1 });
  schema.index({ roleType: 1, isActive: 1 });

  // TTL index para roles con expiración
  schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

  // Índices para restricciones
  schema.index({ "companyRestrictions.allowedCompanies": 1 });
  schema.index({ "geographicRestrictions.allowedCountries": 1 });
}
