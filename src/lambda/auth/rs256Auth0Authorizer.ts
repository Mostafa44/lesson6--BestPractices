
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJShx0m2A8mSOFMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi1vM21kbXh4NC51cy5hdXRoMC5jb20wHhcNMjAwOTE1MDU1NTQ3WhcN
MzQwNTI1MDU1NTQ3WjAkMSIwIAYDVQQDExlkZXYtbzNtZG14eDQudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvbHiF3ADhCygOq96
b5BH6vtNSba65b5gLLyEdqluXIZ35FkYXSS6UCd1kuD8mgPo3E6QsHnYvZATUjpy
OAj/r+JB9uO3Plm91rOXIQnLwQhgIY4u8s3g+aIwr/u9JWG197ij6lIVf9IEwsbN
erNAN3WLgRC3WvrzoBc/2Bghq8yu4Tq8LV+zFlYfsfhqeET19RI7VzExs17Ha3D7
44VmaeyjWHVHjrSy8aSkmSgw7UntqfhU78rh2dQ134dkI2Vkb9C62BSjQfQxfz2e
HcwyUyoG7ROMeznTim1gj3Golz3qaPQzrYs5RoDBEl6cX7ubWSpZUsjtAtF429oQ
dxErOwIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSppRprGhkm
P59OctihzDvpcY+tXDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
AGijWezrhll/ciCCyZA4WbMAA/yuol+84+KCtKUyEwocR9LjmdhUvoMKVa/cRcNZ
XRrVR/8EpfIX7+L2qmrk6wyLKxiPcrrHUcVMeniSHBSO+1KiyYZ+GET8C3ar/rqM
S6kQdl0Wy8CKDn7zQXGRtjZW2IiXxjhFge/9Pl4V+cgf+y1pVbAZ/lcqsd3IHhzk
68wutqV3VRe+vx0ZbWGQcLWG7kxsM7NWO7I26MFFmYlcSCFNuA4W6UoL5gENAUcA
jHharjYnd058N+ivnrjsE7oJb5DmrhkuG/U0NsXHevSxOFpB+bmn0U0st7hGvhBx
dpajsuyh8tOefSV2W2zOH/U=
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
