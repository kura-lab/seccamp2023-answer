/*
 * @license
 * Copyright 2023 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

// init project
import path from 'path';
import url from 'url';
const __dirname = url.fileURLToPath(new URL('.', import.meta.url));
import express from 'express';
import session from 'express-session';
import hbs from 'express-handlebars';
const app = express();
import useragent from 'express-useragent';
import { getFirestore } from 'firebase-admin/firestore';
import { FirestoreStore } from '@google-cloud/connect-firestore';
import { auth } from './libs/auth.mjs';

import { Issuer } from 'openid-client';
import { generators } from 'openid-client';

import { Users } from './libs/db.mjs';

const views = path.join(__dirname, 'views');
app.set('view engine', 'html');
app.engine('html', hbs.engine({
  extname: 'html',
  defaultLayout: 'index',
  layoutsDir: path.join(views, 'layouts'),
  partialsDir: path.join(views, 'partials'),
}));
app.set('views', './views');
app.use(express.json());
app.use(useragent.express());
app.use(express.static('public'));
app.use(express.static('dist'));
app.use(session({
  secret: 'secret', // You should specify a real secret here
  resave: true,
  saveUninitialized: false,
  proxy: true,
  store: new FirestoreStore({
    dataset: getFirestore(),
    kind: 'express-sessions',
  }),
  cookie:{
    path: '/',
    httpOnly: true,
    secure: process.env.NODE_ENV !== 'localhost',
    maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year
  }
}));

const RP_NAME = 'Passkeys Demo';

app.use((req, res, next) => {
  process.env.HOSTNAME = req.hostname;
  const protocol = process.env.NODE_ENV === 'localhost' ? 'http' : 'https';
  process.env.ORIGIN = `${protocol}://${req.headers.host}`;
  process.env.RP_NAME = RP_NAME;
  req.schema = 'https';
  return next();
});

app.get('/', (req, res) => {
  // Check session
  if (req.session.username) {
    // If username is known, redirect to `/reauth`.
    return res.redirect(307, '/reauth');
  }
  // If the user is not signed in, show `index.html` with id/password form.
  return res.render('index.html', {
    project_name: process.env.PROJECT_NAME,
    title: RP_NAME,
  });
});

app.get('/one-button', (req, res) => {
  // Check session
  if (req.session.username) {
    // If username is known, redirect to `/reauth`.
    return res.redirect(307, '/reauth');
  }
  // If the user is not signed in, show `index.html` with id/password form.
  return res.render('one-button.html', {
    project_name: process.env.PROJECT_NAME,
    title: RP_NAME,
  });
});

app.get('/reauth', (req, res) => {
  const username = req.session.username;
  if (!username) {
    res.redirect(302, '/');
    return;
  }
  // Show `reauth.html`.
  // User is supposed to enter a password (which will be ignored)
  // Make XHR POST to `/signin`
  res.render('reauth.html', {
    username: username,
    project_name: process.env.PROJECT_NAME,
    title: RP_NAME,
  });
});

app.get('/home', (req, res) => {
  if (!req.session.username || req.session['signed-in'] != 'yes') {
    // If user is not signed in, redirect to `/`.
    res.redirect(307, '/');
    return;
  }
  // `home.html` shows sign-out link
  return res.render('home.html', {
    displayName: req.session.username,
    project_name: process.env.PROJECT_NAME,
    title: RP_NAME,
  });
});

app.get('/.well-known/assetlinks.json', (req, res) => {
  const assetlinks = [];
  const relation = [
    'delegate_permission/common.handle_all_urls',
    'delegate_permission/common.get_login_creds',
  ];
  assetlinks.push({
    relation: relation,
    target: {
      namespace: 'web',
      site: process.env.ORIGIN,
    },
  });
  if (process.env.ANDROID_PACKAGENAME && process.env.ANDROID_SHA256HASH) {
    const package_names = process.env.ANDROID_PACKAGENAME.split(",").map(name => name.trim());
    const hashes = process.env.ANDROID_SHA256HASH.split(",").map(hash => hash.trim());
    for (let i = 0; i < package_names.length; i++) {
      assetlinks.push({
        relation: relation,
        target: {
          namespace: 'android_app',
          package_name: package_names[i],
          sha256_cert_fingerprints: [hashes[i]],
        },
      });
    }
  }
  return res.json(assetlinks);
});

app.get('/.well-known/passkey-endpoints', (req, res) => {
  const web_endpoint = `${process.env.ORIGIN}/home`;
  const enroll = { 'web': web_endpoint };
  const manage = { 'web': web_endpoint };
  return res.json({ enroll, manage });
});

app.use('/auth', auth);

const CLIENT_ID = '551667838986-u04inmb4f3m040k55el9vvl6a73urbj3.apps.googleusercontent.com';
const CLIENT_SECRET = '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';
const REDIRECT_URIS = ['http://localhost:8080/cb'];
const RESPONSE_TYPES = ['code'];
const googleIssuer = await Issuer.discover('https://accounts.google.com');
//console.log('Discovered issuer %s %O', googleIssuer.issuer, googleIssuer.metadata);

app.get('/federate', (req, res) => {
  
  const client = new googleIssuer.Client({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uris: REDIRECT_URIS,
    response_types: RESPONSE_TYPES,
    // id_token_signed_response_alg (default "RS256")
    // token_endpoint_auth_method (default "client_secret_basic")
  }); // => Client

  const nonce = generators.nonce();
  req.session.nonce = nonce;
  console.log('set nonce %0', req.session.nonce);

  const url = client.authorizationUrl({
    //scope: 'openid email profile',
    scope: 'openid',
    nonce: nonce,
    //resource: 'https://my.api.example.com/resource/32178',
    //code_challenge,
    //code_challenge_method: 'S256',
  });

  console.log(url);

  return res.redirect(307, url);
});

app.get('/cb', (req, res, next) => {

  const client = new googleIssuer.Client({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    redirect_uris: REDIRECT_URIS,
    response_types: RESPONSE_TYPES,
    // id_token_signed_response_alg (default "RS256")
    // token_endpoint_auth_method (default "client_secret_basic")
  }); // => Client

  const params = client.callbackParams(req);
  console.log('params %0', params);
  //const tokenSet = await client.callback('https://client.example.com/callback', params, { code_verifier });

  (async () => {

    try {
      console.log('req.session.nonce %0', req.session.nonce);

      const check = {};
      check.nonce = req.session.nonce;

      // verify id token and extract sub claim
      const tokenSet = await client.callback('http://localhost:8080/cb', params, check);

      console.log('received and validated tokens %0', tokenSet);
      console.log('validated ID Token claims %0', tokenSet.claims());


      // relate sub to login session
      console.log('sub %0', tokenSet.claims().sub);

      const sub = tokenSet.claims().sub;

      //_fetch('/auth/registerSub', { sub });

      if (!req.session['signed-in'] || !req.session.username) {
        const user = await Users.findBySub(sub);
        if (!user) {
          console.log('have not created a user');
          return res.redirect(307, '/');
        }
        // Start a new session.
        req.session.username = user.username;
        req.session['signed-in'] = 'yes';
        console.log('sign-in with sub %0', sub);
      } else {
        const user = await Users.findByUsername(req.session.username);
        user.sub = sub;
        await Users.update(user);
        console.log('update sub %0', user);
      }

      return res.redirect(307, '/home');

    } catch (e) {
      console.error(e);
    }

  })().catch(next);;

});

app.get('/social-login', (req, res) => {
  // Check session
  if (req.session.username) {
    // If username is known, redirect to `/reauth`.
    return res.redirect(307, '/reauth');
  }
  // If the user is not signed in, show `index.html` with id/password form.
  return res.render('social-login.html', {
    project_name: process.env.PROJECT_NAME,
    title: RP_NAME,
  });
});

const listener = app.listen(process.env.PORT || 8080, () => {
  console.log('Your app is listening on port ' + listener.address().port);
});
