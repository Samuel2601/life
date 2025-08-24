export function applyPreSaveMiddleware(schema) {
  schema.pre("save", async function (next) {
    if (this.roleName) {
      this.roleName = this.roleName.toLowerCase().trim();
    }

    if (this.parentRole && this.hierarchy !== undefined) {
      try {
        const parentRole = await this.constructor.findById(this.parentRole);
        if (parentRole && this.hierarchy >= parentRole.hierarchy) {
          return next(
            new Error(
              "La jerarquía del rol debe ser menor que la del rol padre"
            )
          );
        }
      } catch (error) {
        return next(error);
      }
    }

    if (this.isDefault && this.isModified("isDefault")) {
      await this.constructor.updateMany(
        { _id: { $ne: this._id } },
        { $set: { isDefault: false } }
      );
    }

    next();
  });
}
