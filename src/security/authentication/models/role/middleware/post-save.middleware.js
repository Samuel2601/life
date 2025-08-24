export function applyPostSaveMiddleware(schema) {
  schema.post("save", function (doc, next) {
    if (doc.isNew) {
      console.log(
        `✅ Rol creado: ${doc.displayName?.original?.text || doc.roleName}`
      );
    }
    next();
  });
}
