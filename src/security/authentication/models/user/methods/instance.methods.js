// =============================================================================
// src/modules/authentication/models/user/methods/instance.methods.js
// =============================================================================
import bcrypt from "bcrypt";
import crypto from "crypto";

/**
 * Configurar métodos de instancia para el schema de Usuario
 * @param {mongoose.Schema} schema - El schema al que agregar los métodos
 */
export function setupInstanceMethods(schema) {
  // Método para validar contraseña
  schema.methods.validatePassword = async function (password) {
    if (!this.passwordHash) return false;

    try {
      return await bcrypt.compare(password, this.passwordHash);
    } catch (error) {
      console.error("Error validando contraseña:", error);
      return false;
    }
  };

  // Método para establecer contraseña
  schema.methods.setPassword = async function (password) {
    if (!password || password.length < 8) {
      throw new Error("La contraseña debe tener al menos 8 caracteres");
    }

    const saltRounds = 12;
    this.passwordHash = await bcrypt.hash(password, saltRounds);
    return this;
  };

  // Método para verificar si está bloqueado
  schema.methods.checkLockStatus = function () {
    return {
      isLocked: this.isLocked,
      lockUntil: this.lockUntil,
      canRetry: !this.isLocked,
    };
  };

  // Método para incrementar intentos de login
  schema.methods.incrementLoginAttempts = async function () {
    // Si ya está bloqueado y el bloqueo ha expirado, resetear
    if (this.lockUntil && this.lockUntil < Date.now()) {
      return this.updateOne({
        $unset: { lockUntil: 1 },
        $set: { loginAttempts: 1 },
      });
    }

    const updates = { $inc: { loginAttempts: 1 } };

    // Bloquear después de 5 intentos fallidos
    if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
      updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 horas
    }

    return this.updateOne(updates);
  };

  // Método para resetear intentos de login exitoso
  schema.methods.resetLoginAttempts = async function () {
    const updates = {
      $unset: { lockUntil: 1 },
      $set: {
        loginAttempts: 0,
        lastLoginAt: new Date(),
        "metadata.lastActiveAt": new Date(),
      },
      $inc: { "metadata.totalLogins": 1 },
    };

    return this.updateOne(updates);
  };

  // Método para conectar proveedor OAuth
  schema.methods.connectOAuthProvider = function (provider, providerData) {
    const allowedProviders = ["google", "facebook", "apple", "microsoft"];

    if (!allowedProviders.includes(provider)) {
      throw new Error(`Proveedor OAuth '${provider}' no es válido`);
    }

    if (!this.oauthProviders) {
      this.oauthProviders = {};
    }

    this.oauthProviders[provider] = {
      providerId: providerData.providerId,
      email: providerData.email,
      isVerified: providerData.isVerified || false,
      connectedAt: new Date(),
      lastUsed: new Date(),
    };

    return this;
  };

  // Método para desconectar proveedor OAuth
  schema.methods.disconnectOAuthProvider = function (provider) {
    if (this.oauthProviders && this.oauthProviders[provider]) {
      this.oauthProviders[provider] = undefined;
    }
    return this;
  };

  // Método para actualizar preferencias
  schema.methods.updatePreferences = function (newPreferences) {
    if (!this.preferences) {
      this.preferences = {};
    }

    // Merge profundo de preferencias
    this.preferences = {
      ...this.preferences,
      ...newPreferences,
      notifications: {
        ...this.preferences.notifications,
        ...newPreferences.notifications,
      },
      privacy: {
        ...this.preferences.privacy,
        ...newPreferences.privacy,
      },
    };

    return this;
  };

  // Método para generar token de verificación de email
  schema.methods.generateEmailVerificationToken = function () {
    const token = crypto.randomBytes(32).toString("hex");

    this.emailVerificationToken = token;
    this.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 horas

    return token;
  };

  // Método para generar token de reset de contraseña
  schema.methods.generatePasswordResetToken = function () {
    const token = crypto.randomBytes(32).toString("hex");

    this.passwordResetToken = token;
    this.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

    return token;
  };

  // Método alternativo para crear token de reset de contraseña (hasheado)
  schema.methods.createPasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString("hex");
    this.passwordResetToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");
    this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // 10 minutes
    return resetToken;
  };

  // Método alternativo para crear token de verificación de email (hasheado)
  schema.methods.createEmailVerificationToken = function () {
    const verificationToken = crypto.randomBytes(32).toString("hex");
    this.emailVerificationToken = crypto
      .createHash("sha256")
      .update(verificationToken)
      .digest("hex");
    this.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    return verificationToken;
  };
}
