export function applyRoleVirtuals(schema) {
  schema.virtual("isExpired").get(function () {
    return this.expiresAt && this.expiresAt < new Date();
  });

  schema.virtual("canAssignMoreUsers").get(function () {
    if (!this.maxUsers) return true;
    return this.stats.userCount < this.maxUsers;
  });

  schema.virtual("usagePercentage").get(function () {
    if (!this.maxUsers) return 0;
    return Math.round((this.stats.userCount / this.maxUsers) * 100);
  });

  schema.virtual("securityLevel").get(function () {
    if (this.hierarchy >= 90) return "critical";
    if (this.hierarchy >= 70) return "high";
    if (this.hierarchy >= 40) return "medium";
    return "standard";
  });
}
