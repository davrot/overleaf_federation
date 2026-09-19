// B-side read-only preview: invited (03 §4.2).
//
// A asks B "does `invitee.localName` live on B, and is it usable for a
// federated invite?" — the invite-UX blur check (05 §8.1). The response
// is SOFT: it is ALWAYS the ok envelope (a preview, not a decision);
// `payload.approved` distinguishes the preview outcomes. Not-found is a
// valid preview result, NOT a refusal (no `*_unknown` code).
//
// Rate-limited by the router (03 §5, 30 / 120 s keyed (caller,
// localNameHash)); cached 60 s on A (util/RateLimitStore invitation
// cache), not on B.
import { User } from '../../../../app/src/models/User.mjs'

import { getOrigin } from '../../oidf/leaf.mjs'

export default async function invited({ body, callerOrigin }) {
  const invitee = body?.payload?.invitee
  const localName = invitee?.localName
  const inviteeOrigin = invitee?.origin

  const softDeny = () => ({
    ok: true,
    payload: { approved: false, displayName: null },
  })
  if (
    !invitee ||
    typeof localName !== 'string' ||
    localName.length === 0 ||
    typeof inviteeOrigin !== 'string' ||
    inviteeOrigin !== getOrigin()
  ) {
    return softDeny()
  }

  const user = await User.findOne({ email: localName }).lean()
  if (!user || user.suspended) {
    return softDeny()
  }

  const displayName =
    `${user.first_name || ''} ${user.last_name || ''}`.trim() || user.email

  return {
    ok: true,
    payload: { approved: true, displayName },
  }
}
