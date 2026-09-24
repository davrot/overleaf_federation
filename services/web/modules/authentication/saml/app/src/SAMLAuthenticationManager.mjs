import crypto from 'node:crypto'
import Settings from '@overleaf/settings'
import UserCreator from '../../../../../app/src/Features/User/UserCreator.mjs'
import { ParallelLoginError } from '../../../../../app/src/Features/Authentication/AuthenticationErrors.mjs'
import SAMLIdentityManager from '../../../../../app/src/Features/User/SAMLIdentityManager.mjs'
import { User } from '../../../../../app/src/models/User.mjs'
import { getProviderById } from '../../../ssoConfigLoader.mjs'

const SAMLAuthenticationManager = {
  /**
   * Per-provider SAML user resolution (N-provider, P1b).
   *
   *  - samlProviderId: identifier key for `samlIdentifiers` and the
   *    SAMLIdentityManager lookup. Env mode → '1' (legacy stock contract);
   *    DB mode → the ssoConfigs provider row id.
   *  - attribute fields: live per-provider config in DB mode (admin edits
   *    apply without restart); env mode falls back to Settings.saml singleton.
   *
   * @param {object} profile  per-provider parsed attribute map
   * @param {object} auditLog
   * @param {object} opts.providerId  provider row id (DB) or env legacy id '1'
   */
  async findOrCreateUser(profile, auditLog, { providerId, ssoRole } = {}) {
    const provider = await getProviderById(providerId)
    const isDbProvider = !!(provider && !provider.__envFallback)
    const samlProviderId = isDbProvider ? providerId : '1'
    const dbCfg = isDbProvider ? {
      attUserId:    provider.userIdField || 'eduPersonPrincipalName',
      attEmail:     provider.emailField || 'email',
      attFirstName: provider.firstNameField || 'givenName',
      attLastName:  provider.lastNameField || 'displayName',
      attAdmin:     provider.isAdminField || 'isSamlAdmin',
      valAdmin:     provider.isAdminFieldValue || '1',
      updateUserDetailsOnLogin: !!provider.updateUserDetailsOnLogin,
    } : null
    const cfg = dbCfg || Settings.saml?.providers?.[samlProviderId] || Settings.saml
    const {
      attUserId,
      attEmail,
      attFirstName,
      attLastName,
      attAdmin,
      valAdmin,
      updateUserDetailsOnLogin,
    } = cfg
    const externalUserId = profile[attUserId]
    // R1 (plan 10 §3 Phase 2): eduGAIN/DFN + GEANT IdPs do NOT guarantee an
    // `email` attribute. When absent but the identity anchor (eppn/nameID) is
    // present, JIT a synthetic `<userpart>@<domain>` and flag it so the
    // identifier can be distinguished from a real email. Domain = env
    // OVERLEAF_SAML_SYNTHETIC_EMAIL_DOMAIN or this origin's siteUrl host.
    const emailRaw = Array.isArray(profile[attEmail])
      ? profile[attEmail][0]
      : profile[attEmail]
    let email
    let syntheticEmail = false
    if (emailRaw && String(emailRaw).trim() !== '') {
      email = String(emailRaw).toLowerCase()
    } else {
      const userpart = externalUserId ? String(externalUserId).split('@')[0].trim() : ''
      if (!userpart) {
        throw new Error(`SAML login (provider ${samlProviderId}): no email attribute and no eppn/nameID to JIT from`)
      }
      const domain = process.env.OVERLEAF_SAML_SYNTHETIC_EMAIL_DOMAIN
        || new URL(Settings.siteUrl).host
      email = `${userpart}@${domain}`
      syntheticEmail = true
    }
    const firstName = attFirstName ? profile[attFirstName] : ""
    const lastName  = attLastName  ? profile[attLastName] : email
    let isAdmin = false
    if (attAdmin && valAdmin) {
      isAdmin = (Array.isArray(profile[attAdmin]) ? profile[attAdmin].includes(valAdmin) :
                                                    profile[attAdmin] === valAdmin)
    }
// We search for a SAML user, and if none is found, we search for a user with the given email. If a user is found,
// we update the user to be a SAML user, otherwise, we create a new SAML user with the given email. In the case of
// multiple SAML IdPs, one would have to do something similar, or possibly report an error like
// 'the email is associated with the wrong IdP'
    let user = await SAMLIdentityManager.getUser(samlProviderId, externalUserId, attUserId)
    if (!user) {
      user = await User.findOne({ 'email': email }).exec()
      if (!user) {
        user = await UserCreator.promises.createNewUser(
          {
            email: email,
            first_name: firstName,
            last_name: lastName,
            isAdmin: isAdmin,
            holdingAccount: false,
            samlIdentifiers: [{
              providerId: samlProviderId,
              ...(syntheticEmail ? { syntheticEmail: true } : {}),
            }],
            analyticsId: crypto.randomUUID(),
          }
        )
      }
      // cannot use SAMLIdentityManager.linkAccounts because affilations service is not there
      const setOps = {
        'emails.0.confirmedAt': Date.now(), //email of saml user is confirmed
        'emails.0.samlProviderId': samlProviderId,
        'samlIdentifiers.0.providerId': samlProviderId,
        'samlIdentifiers.0.externalUserId': externalUserId,
        'samlIdentifiers.0.userIdAttribute': attUserId,
      }
      // R1: flag synthetic-email identifiers (absent = real email).
      if (syntheticEmail) setOps['samlIdentifiers.0.syntheticEmail'] = true
      await User.updateOne(
        { _id: user._id },
        { $set: setOps }
      ).exec()
    }
    // We only want to update the user if the user is a SAML user
    let userDetails = updateUserDetailsOnLogin ? { first_name : firstName, last_name: lastName } : {}
    if (attAdmin && valAdmin) {
      user.isAdmin = isAdmin
      userDetails.isAdmin = isAdmin
    }
    // P1c: persist the role the controller evaluated from attrFilter (before user
    // lookup creates nothing here for a `blocked` user) + the current-SSO-login
    // marker used by the project-creation refusal check. Re-evaluated every
    // login (G4). Keyed on samlProviderId (env '1' / DB row id).
    userDetails['ssoRoles.' + samlProviderId] = {
      role: ssoRole || 'local',
      at: Date.now(),
    }
    userDetails.ssoLoginProviderId = samlProviderId
    const result = await User.updateOne(
      { _id: user._id, loginEpoch: user.loginEpoch },
      {
        $inc: { loginEpoch: 1 },
        $set: userDetails,
        $unset: { hashedPassword: "" },
      },
    ).exec()
    if (result.modifiedCount !== 1) {
      throw new ParallelLoginError()
    }
    return user
  },
}

export default {
  promises: SAMLAuthenticationManager,
}
