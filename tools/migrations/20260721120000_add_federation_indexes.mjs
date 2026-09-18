import Helpers from './lib/helpers.mjs'

const tags = ['server-ce', 'server-pro']

// 04-data-model §9 — federation index additions (P0–P2).
//
// users: (federation.origin, federation.localName), UNIQUE, partial on
//   the subdoc's presence (04 §9: "partialFilterExpression
//   { federation: { $exists: true } }"; the two-field query discipline is
//   the contract, the index enforces it).
// projectInvites: (federated.origin, federated.localName), partial on
//   federated-subdoc presence (dedup on re-`federate` for the same
//   tuple, 04 §9).
// projectAuditLogEntries: federated_* audit rows (04 §8);
//   (operation, info.origin) composite for the cross-admin audit view.
//   (`ProjectAuditLogEntry.info` is the model's free-form `meta` slot,
//   so the origin filter indexes `info.origin`.)
const usersIndexes = [
  {
    name: 'federation_origin_localName_unique_1',
    key: { 'federation.origin': 1, 'federation.localName': 1 },
    unique: true,
    partialFilterExpression: { federation: { $exists: true } },
  },
]
const inviteIndexes = [
  {
    name: 'federated_origin_localName_1',
    key: { 'federated.origin': 1, 'federated.localName': 1 },
    partialFilterExpression: { federated: { $exists: true } },
  },
]
const auditIndexes = [
  {
    name: 'federation_audit_operation_origin_1',
    key: { operation: 1, 'info.origin': 1 },
  },
]

const migrate = async client => {
  const { db } = client
  await Helpers.addIndexesToCollection(db.users, usersIndexes)
  await Helpers.addIndexesToCollection(db.projectInvites, inviteIndexes)
  await Helpers.addIndexesToCollection(db.projectAuditLogEntries, auditIndexes)
}

const rollback = async client => {
  const { db } = client
  await Helpers.dropIndexesFromCollection(db.users, usersIndexes)
  await Helpers.dropIndexesFromCollection(db.projectInvites, inviteIndexes)
  await Helpers.dropIndexesFromCollection(db.projectAuditLogEntries, auditIndexes)
}

export default {
  tags,
  migrate,
  rollback,
}
