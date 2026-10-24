"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { analyse } = require("../risk-classifier");

test("MD5 is critical", () => assert.equal(analyse({algorithm:"MD5",type:"hash"}).risk,"critical"));
test("RSA-2048 is quantum-vulnerable but not automatically critical", () => {
  const r=analyse({algorithm:"RSA",keySize:2048,language:"Java"});
  assert.equal(r.quantum,"vulnerable");
  assert.equal(r.risk,"medium");
});
test("ML-KEM is quantum-resistant and not critical", () => {
  const r=analyse({algorithm:"ML-KEM-768"});
  assert.equal(r.quantum,"resistant");
  assert.notEqual(r.risk,"critical");
});
test("AES-256-GCM is not classified as weak", () => {
  const r=analyse({algorithm:"AES-256-GCM",keySize:256,mode:"GCM"});
  assert.equal(r.risk,"safe");
  assert.equal(r.quantum,"resistant");
});
