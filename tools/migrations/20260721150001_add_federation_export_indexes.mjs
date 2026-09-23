import Helpers from './lib/helpers.mjs'

const tags = ['server-ce', 'server-pro']

// 09 §3.1 — B-side export grant ledger.
//
// federationExportGrants: (owner, status) — the 2c sweep walks
// "expired/active grants per owner" and "all expired grants"; both are
// owner-first or status-first scans. (expiresAt) supports the expiry purge.
const exportGrantIndexes = [
  { name: 'owner_status_1', key: { owner: 1, status: 1 } },
  { name: 'expires_at_1', key: { expiresAt: 1 } },
]

const migrate = async client => {
  const { db } = client
  await Helpers.addIndexesToCollection(
    db.federationExportGrants,
    exportGrantIndexes,
  )
}

const rollback = async client => {
  const { db } = client
  await Helpers.dropIndexesFromCollection(
    db.federationExportGrants,
    exportGrantIndexes,
  )
}

export default {
  tags,
  migrate,
  rollback,
}
