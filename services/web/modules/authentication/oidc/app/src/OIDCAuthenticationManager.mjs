import crypto from 'node:crypto'
import Settings from '@overleaf/settings'
import UserCreator from '../../../../../app/src/Features/User/UserCreator.mjs'
import ThirdPartyIdentityManager from '../../../../../app/src/Features/User/ThirdPartyIdentityManager.mjs'
import { ParallelLoginError } from '../../../../../app/src/Features/Authentication/AuthenticationErrors.mjs'
import { User } from '../../../../../app/src/models/User.mjs'
import { getProviderById } from '../../../ssoConfigLoader.mjs'

const OIDCAuthenticationManager = {
  /**
   * @param {object} profile  passport-openidconnect profile payload
   * @param {object} auditLog
   * @param {object} opts.providerId  provider row id (DB) or env synthetic id
   */
  async findOrCreateUser(profile, auditLog, { providerId, ssoRole } = {}) {
    const provider = await getProviderById(providerId)
    const envCfg = Settings.oidc
    const isDbProvider = provider && !provider.__envFallback
    const cfg = isDbProvider ? {
      attUserId:    provider.userIdField || 'id',
      attAdmin:     provider.isAdminField || undefined,
      valAdmin:     provider.isAdminFieldValue || undefined,
      updateUserDetailsOnLogin: !!provider.updateUserDetailsOnLogin,
      allowedOIDCEmailDomains: provider.allowedEmailDomains
        ? provider.allowedEmailDomains.split(',').map(s => s.trim()).filter(Boolean)
        : null,
    } : envCfg
    const attUserId = cfg.attUserId
    const attAdmin = cfg.attAdmin
    const valAdmin = cfg.valAdmin
    const updateUserDetailsOnLogin = cfg.updateUserDetailsOnLogin
    // Link key: DB rows link by providerID (admin-configurable identity anchor,
    // default 'oidc' per provider row) — mirrors the pre-N OIDC link contract.
    const linkProviderId = isDbProvider
      ? (provider.providerID || providerId)
      : (providerId || envCfg?.providerId || envCfg?._firstProviderId || 'oidc')
    const email = profile.emails[0].value
    const oidcUserId = (attUserId === 'email') ? email : profile[attUserId]
    const firstName = profile.name?.givenName || ""
    const lastName  = profile.name?.familyName || ""
    let isAdmin = false
    if (attAdmin && valAdmin) {
      if (attAdmin === 'email') {
        isAdmin = (email === valAdmin)
      } else {
        const adminClaim = profile[attAdmin] || profile._json?.[attAdmin]
        isAdmin = (adminClaim === valAdmin)
      }
    }
    const oidcUserData = null // Possibly it can be used later
    let user
    try {
      user = await ThirdPartyIdentityManager.promises.login(linkProviderId, oidcUserId, oidcUserData)
    } catch {
// A user with the specified OIDC ID and provider ID is not found. Search for a user with the given email.
// If no user exists with this email, create a new user and link the OIDC account to it (provided this is allowed by allowedOIDCEmailDomains).
// If a user exists but no account from the specified OIDC provider is linked to this user, link the OIDC account to this user.
// If an account from the specified provider is already linked to this user, unlink it, and link the OIDC account to this user.
// (Is it safe? Consider: If an account from the specified provider is already linked to this user, throw an error)
      user = await User.findOne({ 'email': email }).exec()
      if (!user) {
        const allowedDomains = cfg.allowedOIDCEmailDomains
        if (
          allowedDomains &&
          !allowedDomains.some(pattern => {
            const domain = email.split('@')[1]
            if (pattern.startsWith('*.')) {
              const base = pattern.slice(2)
              return domain.endsWith(`.${base}`)
            }
            return domain === pattern
          })
        ) {
          return null
        }
        user = await UserCreator.promises.createNewUser(
          {
            email: email,
            first_name: firstName,
            last_name: lastName,
            isAdmin: isAdmin,
            holdingAccount: false,
            analyticsId: crypto.randomUUID(),
          }
        )
      }
//    If the user is not found by OIDC, search for a user with the given email. If a user is found, check if an account from the specified OIDC provider is linked; if so, throw an error; otherwise, link the account to this user.
      auditLog.initiatorId = user._id
      await ThirdPartyIdentityManager.promises.link(user._id, linkProviderId, oidcUserId, oidcUserData, auditLog)
      await User.updateOne(
        { _id: user._id },
        { $set : {
           'emails.0.confirmedAt': Date.now(), //email of external user is confirmed
          },
        }
      ).exec()
    }

    let userDetails = updateUserDetailsOnLogin ? { first_name : firstName, last_name: lastName } : {}
    if (attAdmin && valAdmin) {
      user.isAdmin = isAdmin
      userDetails.isAdmin = isAdmin
    }
    // P1c: persist the role the controller evaluated from attrFilter (blocked users
    // never reach here) + the current-SSO-login marker (G4: re-eval each login),
    // keyed on the login providerId.
    userDetails['ssoRoles.' + providerId] = {
      role: ssoRole || 'local',
      at: Date.now(),
    }
    userDetails.ssoLoginProviderId = providerId
    const result = await User.updateOne(
      { _id: user._id, loginEpoch: user.loginEpoch }, { $inc: { loginEpoch: 1 }, $set: userDetails },
      {}
    ).exec()

    if (result.modifiedCount !== 1) {
      throw new ParallelLoginError()
    }
    return user
  },
  async linkAccount(userId, profile, auditLog, { providerId } = {}) {
    const envCfg = Settings.oidc
    const provider = await getProviderById(providerId)
    const isDbProvider = !!provider && !provider.__envFallback
    const attUserId = isDbProvider ? (provider.userIdField || 'id') : envCfg.attUserId
    const linkProviderId = isDbProvider
      ? (provider.providerID || providerId)
      : (providerId || envCfg?.providerId || envCfg?._firstProviderId || 'oidc')
    const oidcUserId = (attUserId === 'email') ? profile.emails[0].value : profile[attUserId]
    const oidcUserData = null // Possibly it can be used later
    await ThirdPartyIdentityManager.promises.link(userId, linkProviderId, oidcUserId, oidcUserData, auditLog)
  },
}

export default {
  promises: OIDCAuthenticationManager,
}
