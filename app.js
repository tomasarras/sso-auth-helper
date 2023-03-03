require('dotenv').config();
const express = require('express');
const app = express();
const crypto = require('crypto');
const redis = require('redis');
const jwt = require('jsonwebtoken');
const redisClient = redis.createClient({
  socket: {
    host: process.env.REDIS_HOST,
    port: process.env.REDIS_PORT,
  },
  password: process.env.REDIS_PASSWORD,
});
redisClient.on('error', err => console.log('Redis error ' + err));
redisClient.connect();
const bodyparser = require('body-parser');
app.use(bodyparser.urlencoded({ extended: false }));
app.use(bodyparser.json());

const PORT = process.env.PORT || 3001;
const TOKEN_SECRET = process.env.TOKEN_SECRET;
const SSO_PROVIDER_SECRET = process.env.SSO_PROVIDER_SECRET;
const DISCOURSE_ROOT_URL = process.env.DISCOURSE_ROOT_URL;
const NONCE_EXPIRES_IN_SECONDS = process.env.NONCE_EXPIRES_IN_SECONDS;

/**
 * Saves the nonce in memory to be used later
 * @param {String} nonce to save
 */
const saveNonceInMemory = async nonce => {
  await redisClient.set(nonce, "");
  await redisClient.expire(nonce, NONCE_EXPIRES_IN_SECONDS);
};

/**
 * Generates a unique random nonce and save it in memory to be used later
 * @returns {Promise<String>} nonce generated
 */
const generateRandomNonce = () => new Promise((resolve, reject) => {
  const NONCE_LENGHT = 16;
  crypto.randomBytes(NONCE_LENGHT, async (err, buf) => {
    if (err) {
      console.log(`Error trying to generate nonce, error=${err}`);
      reject(err);
    }
    const nonce = buf.toString("hex");
    await saveNonceInMemory(nonce);
    resolve(nonce);
  });
});

/**
 * Gets the signature of the base64 in hex format 
 * @param {String} base64Payload to be signed
 * @returns {String} hex format of the signed base64Payload
 */
const getHexSignature = base64Payload => crypto.createHmac('sha256', SSO_PROVIDER_SECRET)
  .update(base64Payload)
  .digest('hex')
  .toLowerCase();

/**
 * Compares the sso with the signature
 * @param {String} sso that wants to know if is signed
 * @param {String} sig signature of the sso in hex format
 * @returns {Boolean} true if sso is signed or else false
 */
const isValidSso = (sso, sig) => getHexSignature(sso) === sig;

/**
 * Returns if nonce is valid or not, a nonce is valid if it is exists in memory
 * @param {String} nonce 
 * @returns {Boolean}
 */
const isValidNonce = async (nonce) => {
  const isNonceInMemory = await redisClient.exists(nonce);
  return isNonceInMemory == 1;
};

const base64Encode = string => Buffer.from(string).toString("base64");

const base64Decode = string => Buffer.from(string, "base64").toString("ascii");

/**
 * Deletes a used nonce in memory of the sso. A nonce can be used only one time
 * @param {String} sso 
 */
const deleteNonce = sso => {
  redisClient.del(sso.nonce);
  delete sso.nonce;
};

/**
 * Redirects to the login page of discourse, generating a nonce to be used after user authentication
 * and a return_sso_url with the url when user will request the token after authentication.
 * The generated nonce and return_sso_url they are inside of a payload in base64 and url encoded
 * with a signature of the payload
 */
const redirectToLoginPage = async (req, res) => {
  const meUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
  const nonce = await generateRandomNonce();
  const payload = `nonce=${nonce}&return_sso_url=${meUrl}`;
  const base64Payload = base64Encode(payload);
  const urlEncodedPayload = encodeURIComponent(base64Payload);
  const hexSignature = getHexSignature(base64Payload);
  const redirectUrl = `${DISCOURSE_ROOT_URL}/session/sso_provider?sso=${urlEncodedPayload}&sig=${hexSignature}`;
  res.redirect(redirectUrl);
};

/**
 * After successful login, verifies the sso with the signature (signed by discourse),
 * nonce (exist in memory and not expired), and generate a jwt with all data of the sso
 * @param {Request} req with sso and sig params. sso contains the nonce generated before and all the 
 * data of the user to be added to the json web token. sig is used to validate that the sso is signed
 */
const generateToken = async (req, res) => {
  const { sso, sig } = req.query;
  if (isValidSso(sso, sig)) {
    const urlParams = new URLSearchParams(base64Decode(sso));
    const decodedSso = Object.fromEntries(urlParams);
    const nonce = decodedSso.nonce;
    if (await isValidNonce(nonce)) {
      deleteNonce(decodedSso);
      delete decodedSso.return_sso_url;
      const token = jwt.sign(decodedSso, TOKEN_SECRET);
      res.json({ token });
    } else {
      res.json({ error: "Invalid or expired nonce" });
    }
  } else {
    res.json({ error: "Invalid sso signature" });
  }
};

app.get('/session/sso', async (req, res) => {
  const { sso, sig } = req.query;
  if (sso && sig)
    generateToken(req, res);
  else
    redirectToLoginPage(req, res);
})

app.listen(PORT, () => {
  console.log(`sso auth helper listening on port ${PORT}`)
})