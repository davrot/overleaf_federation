import Helpers from './lib/helpers.mjs'

const tags = ['server-ce', 'server-pro']

// 04-data-model §2 (institutional, 07 §P3) — institutional trust anchor
// rows (autoIndex is off repo-wide; indexes are applied here).
//
// federationTrustAnchors:
//   entityId UNIQUE — one row per configured institutional TA
//   (the model declares the unique index; the migration enforces it).
const trustAnchorIndexes = [
  {
    name: 'entityId_unique_1',
    key: { entityId: 1 },
    unique: true,
  },
]

const migrate = async client => {
  const { db } = client
  await Helpers.addIndexesToCollection(db.federationTrustAnchors, trustAnchorIndexes)
}

const rollback = async client => {
  const { db } = client
  await Helpers.dropIndexesFromCollection(db.federationTrustAnchors, trustAnchorIndexes)
}

export default {
  tags,
  migrate,
  rollback,
}
