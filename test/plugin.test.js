'use strict'

const { test } = require('node:test')
const assert = require('node:assert/strict')

test('plugin factory loads', () => {
  const factory = require('../index.js')
  assert.equal(typeof factory, 'function')
})
