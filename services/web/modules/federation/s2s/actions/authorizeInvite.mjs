// B-side oracle: authorize-invite (03 §4.1), received via S2S.
//
// A (the RP side, `from`) asks B (this instance, `to`/home) to authorize
// a federated invite for a user who lives HERE. B is the home oracle
// (01 §3.2): B resolves its local account from `invitee.localName` and
// decides existence + suspension. A then stores the approved invite on
// its own project invite row (the A-side write, 05 §2).
//
// The response carries ONLY the claim allow-list (01 §8.3, 04 §8):
// `displayName` + `institution` + `approved`. NO `language`, NO
// `avatarUrl` (v1 wire, 03 §4.1 example fields retired; see HANDOFF),
// NO `hashedPassword`/git/zotero/compile config (deny-list, 04 §4).
//
// Machine codes (03 §6): `invitee-unknown`, `invitee-disabled`
// (200 envelope, business refusal — the peer IS known and approved,
// the user just does not exist here / is disabled).
import { User } from '../../../../app/src/models/User.mjs'

import { getOrigin } from '../../oidf/leaf.mjs'
import { S2S_ERRORS } from '../../oidf/verify.mjs'

export default async function authorizeInvite({ body, callerOrigin }) {
  const invitee = body?.payload?.invitee
  const localName = invitee?.localName
  const inviteeOrigin = invitee?.origin

  if (
    !invitee ||
    typeof localName !== 'string' ||
    localName.length === 0 ||
    typeof inviteeOrigin !== 'string'
  ) {
    return {
      ok: false,
      code: S2S_ERRORS.INVITEE_UNKNOWN,
      detail: 'missing invitee anchor',
    }
  }

  // Origin guard (01 §3.2): B can only oracle about users that live on
  // B. The invitee's declared origin MUST be this instance's origin
  // (the wire's `to`); anything else resolves to no local account here.
  if (inviteeOrigin !== getOrigin()) {
    return {
      ok: false,
      code: S2S_ERRORS.INVITEE_UNKNOWN,
      detail: `invitee is not resident at ${callerOrigin}`,
    }
  }

  // Home oracle (01 §3.2): local account keyed by the home login name
  // (user's email convention on this instance).
  const user = await User.findOne({ email: localName }).lean()
  if (!user) {
    return {
      ok: false,
      code: S2S_ERRORS.INVITEE_UNKNOWN,
      detail: `no local account for ${localName}`,
    }
  }
  // `User.suspended`: a disabled account cannot be invited (03 §4.1
  // "user exists, not disabled").
  if (user.suspended) {
    return {
      ok: false,
      code: S2S_ERRORS.INVITEE_DISABLED,
      detail: 'local account is disabled',
    }
  }

  const displayName =
    `${user.first_name || ''} ${user.last_name || ''}`.trim() || user.email

  return {
    ok: true,
    payload: {
      approved: true,
      displayName,
      institution: user.institution || null,
    },
  }
}
