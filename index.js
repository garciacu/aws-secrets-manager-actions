const core = require('@actions/core')
const aws = require('aws-sdk')
const fs = require('fs')
const sodium = require('./libsodium-wrappers')

const outputPath = core.getInput('OUTPUT_PATH')
const secretName = core.getInput('SECRET_NAME') || 'UniteCICD/secrets'

const AWSConfig = {
  accessKeyId: core.getInput('AWS_ACCESS_KEY_ID') || process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: core.getInput('AWS_SECRET_ACCESS_KEY') || process.env.AWS_SECRET_ACCESS_KEY,
  region: core.getInput('AWS_DEFAULT_REGION') || process.env.AWS_DEFAULT_REGION
}

if (core.getInput('AWS_SESSION_TOKEN') || process.env.AWS_SESSION_TOKEN) {
  AWSConfig.sessionToken = core.getInput('AWS_SESSION_TOKEN') || process.env.AWS_SESSION_TOKEN
}

if (core.getInput('HTTP_PROXY') || process.env.HTTP_PROXY) {
  AWSConfig.httpOptions = {
      proxy: core.getInput('HTTP_PROXY') || process.env.HTTP_PROXY
  }
}

const secretsManager = new aws.SecretsManager(AWSConfig)

async function getSecretValue (secretsManager, secretName) {
  return secretsManager.getSecretValue({ SecretId: secretName }).promise()
}

async function encryptSecretValue(secretValue) {
  const secret = secretValue
  const repokey = 'HAfBp4vDJvUx5qscwwFs8/2xlwKdr8nnhrxdywaQyh0='

  var encryptedVar = await sodium.ready.then(() => {
    // Convert Secret & Base64 key to Uint8Array.
    let binkey = sodium.from_base64(repokey, sodium.base64_variants.ORIGINAL)
    let binsec = sodium.from_string(secretValue)

    //Encrypt the secret using LibSodium
    let encBytes = sodium.crypto_box_seal(binsec, binkey)

    // Convert encrypted Uint8Array to Base64
    let output = sodium.to_base64(encBytes, sodium.base64_variants.ORIGINAL)
    return output
  });

  return encryptedVar
}

getSecretValue(secretsManager, secretName).then(resp => {
  const secretString = resp.SecretString
  core.setSecret(secretString)

  if (secretString == null) {
    core.warning(`${secretName} has no secret values`)
    return
  }

  try {
    const parsedSecret = JSON.parse(secretString)
    Object.entries(parsedSecret).forEach(async ([key, value]) => {
      let encryptedValue = await encryptSecretValue(value) 
      console.log(encryptedValue)
      core.setSecret(encryptedValue)
      core.exportVariable(key, encryptedValue)
    })
    if (outputPath) {
      const secretsAsEnv = Object.entries(parsedSecret).map(([key, value]) => `${key}=${value}`).join('\n')
      fs.writeFileSync(outputPath, secretsAsEnv)
    }
  } catch (e) {
    core.warning('Parsing asm secret is failed. Secret will be store in asm_secret')
    core.exportVariable('asm_secret', secretString)
    if (outputPath) {
      fs.writeFileSync(outputPath, secretString)
    }
  }
}).catch(err => {
  core.setFailed(err)
})

exports.getSecretValue = getSecretValue
