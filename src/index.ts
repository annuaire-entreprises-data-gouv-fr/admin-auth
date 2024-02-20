import dotenv from "dotenv";
import express, { Express, Request, Response } from "express";
import { getIronSession, IronSession } from 'iron-session';
import { BaseClient, Issuer, generators } from 'openid-client';
import { getClientIp } from 'request-ip';
import crypto from 'crypto';

dotenv.config();

const app: Express = express();
const port = process.env.PORT || 3000;
const AUTHORIZED_USER_EMAILS = (process.env.AUTHORIZED_USER_EMAILS || '').split(',');
const AUTHORIZED_SIRET = process.env.AUTHORIZED_SIRET || '';

// SESSION
const IRON_SESSION_PWD = process.env.IRON_SESSION_PWD || '';
const COOKIE_NAME = process.env.AUTH_COOKIE_NAME || 'annuaire-entreprises-admin-auth-session';
const COOKIE_DOMAIN = process.env.AUTH_COOKIE_DOMAIN || '127.0.0.1';
const SESSION_TTL = Number.parseInt(process.env.AUTH_SESSION_TTL || '3600')

// OIDC
const CLIENT_ID = process.env.OPENID_CLIENT_ID || '';
const CLIENT_SECRET = process.env.OPENID_CLIENT_SECRET || '';
const ISSUER_URL = process.env.OPENID_URL_DISCOVER || '';
const REDIRECT_URI = process.env.OPENID_REDIRECT_URI || '';
const POST_LOGOUT_REDIRECT_URI = process.env.OPENID_POST_LOGOUT_REDIRECT_URI || '';

// constants to check if the session has been reused
const VERIFY_BROWSER_SIGNATURE = process.env.VERIFY_BROWSER_SIGNATURE == '1'
const VERIFY_IP_ADDRESS = process.env.VERIFY_IP_ADDRESS == '1'

const SCOPES = 'openid email siret';

let openidClient = undefined as BaseClient | undefined;

type Session = {
  email?: string;
  siret?: string;

  ip?: string | null;
  signature?: string;

  // OIDC Issuer
  state?: string;
  nonce?: string;
  idToken?: string;

  // connexion
  pathFrom?: string;
};

type OpenConnectUserInfo = {
  email: string;
  email_verified: boolean;
};

const getSession = async (req: Request, res: Response) => {
  return await getIronSession<Session>(req, res, {
    password: IRON_SESSION_PWD,
    cookieName: COOKIE_NAME,
    ttl: SESSION_TTL,
    cookieOptions: {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: SESSION_TTL - 60,
      domain: COOKIE_DOMAIN,
    }
  });
}

const getOpenIDClient = async () => {
  if (openidClient) {
    return openidClient;
  } else {
    const issuer = await Issuer.discover(ISSUER_URL);

    openidClient = new issuer.Client({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uris: [REDIRECT_URI],
      post_logout_redirect_uris: [POST_LOGOUT_REDIRECT_URI],
      userinfo_signed_response_alg: 'RS256',
    });

    return openidClient;
  }
};

const getBrowserSignature = (req: Request) => {
  const headers = [
    'user-agent',
    'accept',
    'accept-language',
    'accept-encoding',
  ]

  const raw = headers.map(header => req.headers[header] || '').join('\n')
  const signature = crypto.createHash('md5').update(raw).digest('hex')

  return signature
}

const logMessage = (message: string) => {
  const currentDate = (new Date()).toISOString()
  console.log(`[${currentDate}] ${message}`)
}

app.get('/admin/auth/api', async (req: Request, res: Response) => {
  const session = await getSession(req, res);
  const clientIp = getClientIp(req)

  logMessage(`${req.headers['x-original-uri']} ${session.email} ${clientIp}`)

  if (!session.email) {
    res.sendStatus(401)
    return
  }

  if (VERIFY_IP_ADDRESS) {
    if (session.ip && session.ip !== clientIp) {
      logMessage(`User IP address has changed : email : ${session.email}, old ip : ${session.ip}, new ip : ${clientIp}`)
      await session.destroy()
      res.sendStatus(401)
      return
    }
  }

  if (VERIFY_BROWSER_SIGNATURE && !req.headers['content-type']) {
    const signature = getBrowserSignature(req)

    if (session.signature !== signature) {
      logMessage(`Browser signature has changed : email : ${session.email}, old signature : ${session.signature}, new signature : ${signature}`)
      await session.destroy()
      res.sendStatus(401)
      return
    }
  }

  if (AUTHORIZED_SIRET.length > 0 && AUTHORIZED_SIRET !== session.siret) {
    logMessage(`User is unauthorized : email : ${session.email} - siret : ${session.siret}`)
    res.sendStatus(403)
    return
  }

  if (AUTHORIZED_USER_EMAILS.indexOf(session.email) === -1) {
    logMessage(`User is unauthorized : email : ${session.email} - siret : ${session.siret}`)
    res.sendStatus(403)
    return
  }

  res.sendStatus(200)
})

app.get('/admin/auth/login', async (req: Request, res: Response) => {
  const nonce = generators.nonce();
  const state = generators.state();

  const session = await getSession(req, res);
  session.ip = getClientIp(req);
  session.signature = getBrowserSignature(req);
  session.state = state;
  session.nonce = nonce;

  if (typeof req.headers['x-original-uri'] === 'string') {
    session.pathFrom = req.headers['x-original-uri'];
  }

  await session.save()

  const client = await getOpenIDClient();

  const authUrl = client.authorizationUrl({
    scope: SCOPES,
    acr_values: 'eidas1',
    response_type: 'code',
    nonce,
    state,
  });

  res.redirect(authUrl)
})

app.get('/api/auth/agent-connect/callback', async (req: Request, res: Response) => {
  const client = await getOpenIDClient();

  const params = client.callbackParams(req);

  const tokenSet = await client.grant({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: REDIRECT_URI,
    scope: SCOPES,
  });

  const accessToken = tokenSet.access_token;

  if (!accessToken) {
    res.sendStatus(403)
    return
  }

  const userInfo = (await client.userinfo(tokenSet)) as OpenConnectUserInfo;

  console.log(`Authenticated : {userInfo.email}`)

  const session = await getSession(req, res);

  session.idToken = tokenSet.id_token;
  session.email = userInfo.email;
  session.ip = getClientIp(req);
  session.signature = getBrowserSignature(req);

  await session.save()

  res.status(302)

  if (session.pathFrom) {
    res.location(session.pathFrom)
  } else {
    res.location('/')
  }

  res.send()
})

app.get('/admin/auth/logout-callback', async (req: Request, res: Response) => {
  const session = await getSession(req, res);
  await session.destroy()

  res.sendStatus(200)
})

app.listen(port, () => {
  console.log(`Listening on port ${port}`)
})
