import { describe, expect, test } from 'vitest'
import { Oauth2Error } from '../../../error/Oauth2Error.js'
import {
  type CoseAlgorithmIdentifier,
  fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray,
  fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm,
  jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray,
  jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm,
} from '../algorithm-transform.js'

describe('algorithm-transform', () => {
  describe('jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm', () => {
    test('should transform EdDSA algorithms', () => {
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('Ed25519')).toBe(-19)
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('Ed448')).toBe(-53)
    })

    test('should transform deprecated polymorphic EdDSA algorithm', () => {
      // EdDSA is deprecated in JWA (RFC 9864 Section 4.1.2)
      // Maps to Ed25519 as it's the most common use case
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('EdDSA')).toBe(-19)
    })

    test('should transform ECDSA algorithms', () => {
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('ES256')).toBe(-9)
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('ES384')).toBe(-51)
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('ES512')).toBe(-52)
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('ES256K')).toBe(-47)
    })

    test('should transform RSA algorithms', () => {
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('RS256')).toBe(-257)
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('RS384')).toBe(-258)
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('RS512')).toBe(-259)
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('PS256')).toBe(-37)
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('PS384')).toBe(-38)
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('PS512')).toBe(-39)
    })

    test('should return undefined for unknown algorithms', () => {
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('UnknownAlg')).toBeUndefined()
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('HS256')).toBeUndefined()
    })
  })

  describe('fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm', () => {
    test('should transform EdDSA algorithms', () => {
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-19)).toBe('Ed25519')
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-53)).toBe('Ed448')
    })

    test('should transform ECDSA algorithms', () => {
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-9)).toBe('ES256')
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-51)).toBe('ES384')
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-52)).toBe('ES512')
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-47)).toBe('ES256K')
    })

    test('should transform deprecated polymorphic ECDSA algorithms', () => {
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-7)).toBe('ES256')
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-35)).toBe('ES384')
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-36)).toBe('ES512')
    })

    test('should transform deprecated polymorphic EdDSA algorithm', () => {
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-8)).toBe('Ed25519')
    })

    test('should transform RSA algorithms', () => {
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-257)).toBe('RS256')
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-258)).toBe('RS384')
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-259)).toBe('RS512')
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-37)).toBe('PS256')
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-38)).toBe('PS384')
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(-39)).toBe('PS512')
    })

    test('should return undefined for unknown algorithms', () => {
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(999)).toBeUndefined()
      expect(fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(0)).toBeUndefined()
    })
  })

  describe('jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray', () => {
    test('should transform array of JWA algorithms to COSE', () => {
      const jwaAlgs = ['Ed25519', 'ES256', 'ES384']
      const coseAlgs = jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray(jwaAlgs)
      expect(coseAlgs).toEqual([-19, -9, -51])
    })

    test('should filter out unknown algorithms', () => {
      const jwaAlgs = ['Ed25519', 'UnknownAlg', 'ES256']
      const coseAlgs = jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray(jwaAlgs)
      expect(coseAlgs).toEqual([-19, -9])
    })

    test('should throw error for unknown algorithms if enabled', () => {
      const jwaAlgs = ['Ed25519', 'UnknownAlg', 'ES256']
      expect(() => jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray(jwaAlgs, true)).toThrow(Oauth2Error)
    })

    test('should handle empty array', () => {
      expect(jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray([])).toEqual([])
    })

    test('should handle array with all unknown algorithms', () => {
      const jwaAlgs = ['Unknown1', 'Unknown2']
      const coseAlgs = jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray(jwaAlgs)
      expect(coseAlgs).toEqual([])
    })
  })

  describe('fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray', () => {
    test('should transform array of COSE algorithms to JWA', () => {
      const coseAlgs = [-19, -9, -51]
      const jwaAlgs = fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray(coseAlgs)
      expect(jwaAlgs).toEqual(['Ed25519', 'ES256', 'ES384'])
    })

    test('should transform deprecated COSE algorithms', () => {
      const coseAlgs = [-7, -8, -9]
      const jwaAlgs = fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray(coseAlgs)
      expect(jwaAlgs).toEqual(['ES256', 'Ed25519', 'ES256'])
    })

    test('should filter out unknown algorithms', () => {
      const coseAlgs = [-19, 999, -9]
      const jwaAlgs = fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray(coseAlgs)
      expect(jwaAlgs).toEqual(['Ed25519', 'ES256'])
    })

    test('should throw error for unknown algorithms if enabled', () => {
      const coseAlgs = [-19, 999, -9]
      expect(() => fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray(coseAlgs, true)).toThrow(Oauth2Error)
    })

    test('should handle empty array', () => {
      expect(fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray([])).toEqual([])
    })

    test('should handle array with all unknown algorithms', () => {
      const coseAlgs = [999, 1000]
      const jwaAlgs = fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray(coseAlgs)
      expect(jwaAlgs).toEqual([])
    })
  })

  describe('round-trip transformations', () => {
    test('JWA -> COSE -> JWA should preserve algorithm', () => {
      const jwaAlg = 'Ed25519'
      const coseAlg = jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm(jwaAlg)
      const backToJwa = fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(coseAlg as CoseAlgorithmIdentifier)
      expect(backToJwa).toBe(jwaAlg)
    })

    test('should handle ES256 round-trip', () => {
      const jwaAlg = 'ES256'
      const coseAlg = jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm(jwaAlg)
      expect(coseAlg).toBe(-9) // ESP256
      const backToJwa = fullySpecifiedCoseAlgorithmToJwaSignatureAlgorithm(coseAlg as CoseAlgorithmIdentifier)
      expect(backToJwa).toBe(jwaAlg)
    })

    test('should handle array round-trip', () => {
      const jwaAlgs = ['Ed25519', 'ES256', 'ES384']
      const coseAlgs = jwaSignatureAlgorithmArrayToFullySpecifiedCoseAlgorithmArray(jwaAlgs)
      const backToJwa = fullySpecifiedCoseAlgorithmArrayToJwaSignatureAlgorithmArray(coseAlgs)
      expect(backToJwa).toEqual(jwaAlgs)
    })
  })

  describe('RFC 9864 compliance', () => {
    test('should map EdDSA according to RFC 9864 Table 2', () => {
      // From RFC 9864 Section 2.2, Table 2
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('Ed25519')).toBe(-19)
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('Ed448')).toBe(-53)
    })

    test('should map ECDSA according to RFC 9864 Table 1', () => {
      // From RFC 9864 Section 2.1, Table 1
      // Note: JWA uses ES256/ES384/ES512 which map to COSE ESP256/ESP384/ESP512
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('ES256')).toBe(-9) // ESP256
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('ES384')).toBe(-51) // ESP384
      expect(jwaSignatureAlgorithmToFullySpecifiedCoseAlgorithm('ES512')).toBe(-52) // ESP512
    })
  })
})
