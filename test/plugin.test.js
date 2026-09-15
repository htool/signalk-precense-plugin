'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')
const { presenceUpdateValues, PATH_PREFIX } = require('../index.js')

const t0 = 1700000000000
const iso0 = new Date(t0).toISOString()
const t1 = t0 + 30000
const iso1 = new Date(t1).toISOString()

function paths (values) {
  return values.map((v) => v.path)
}

test('plugin factory loads', () => {
  const factory = require('../index.js')
  assert.equal(typeof factory, 'function')
})

test('first poll publishes boolean, lastSeen and ip', () => {
  const values = presenceUpdateValues('shelly', true, t0, '192.168.2.20', {})
  assert.deepEqual(paths(values), [
    PATH_PREFIX + '.shelly',
    PATH_PREFIX + '.shelly.lastSeen',
    PATH_PREFIX + '.shelly.ip'
  ])
  assert.equal(values[0].value, true)
  assert.equal(values[1].value, iso0)
  assert.equal(values[2].value, '192.168.2.20')
})

test('same present state omits boolean; lastSeen still written', () => {
  const sent = { present: true, lastSeen: iso0, ip: '192.168.2.20' }
  const values = presenceUpdateValues('shelly', true, t1, '192.168.2.20', sent)
  assert.deepEqual(paths(values), [PATH_PREFIX + '.shelly.lastSeen'])
  assert.equal(values[0].value, iso1)
})

test('present → absent publishes boolean false and lastSeen', () => {
  const sent = { present: true, lastSeen: iso0, ip: '192.168.2.20' }
  const values = presenceUpdateValues('shelly', false, t0, '192.168.2.20', sent)
  assert.deepEqual(paths(values), [
    PATH_PREFIX + '.shelly',
    PATH_PREFIX + '.shelly.lastSeen'
  ])
  assert.equal(values[0].value, false)
  assert.equal(values[1].value, iso0)
})

test('absent stay omits boolean; lastSeen still written', () => {
  const sent = { present: false, lastSeen: iso0, ip: '192.168.2.20' }
  const values = presenceUpdateValues('shelly', false, t0, '192.168.2.20', sent)
  assert.deepEqual(paths(values), [PATH_PREFIX + '.shelly.lastSeen'])
  assert.equal(values[0].value, iso0)
})

test('never-seen lastSeen is only sent once', () => {
  const first = presenceUpdateValues('phone', false, null, null, {})
  assert.ok(paths(first).includes(PATH_PREFIX + '.phone.lastSeen'))
  const sent = { present: false, lastSeen: null, ip: null }
  const second = presenceUpdateValues('phone', false, null, null, sent)
  assert.deepEqual(second, [])
})
